"""Built-in self-update: check GitHub releases, verify, install, and roll back.

Trust model (see docs/SECURITY.md): everything is fetched over HTTPS from GitHub hosts only.
  * Preferred artifact: the release asset `bant-<version>.tar.gz`, verified against the release's
    `SHA256SUMS` asset.
  * Fallback (e.g. releases without assets): GitHub's source archive of the release tag, accepted only
    if the commit id embedded in the archive equals the commit the tag points to according to the API.
There are no signatures yet, so this protects against corruption and mix-ups, not against a
compromised GitHub account. Updates are never applied automatically unless you set that up yourself;
the optional daily timer only *checks*.

The new version is installed by the new release's own `install.sh --no-setup`, so releases can ship new
units or files; the previous program directory is kept as `lib.prev` for `self-update rollback`.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bant import __version__
from bant.context import Context
from bant.errors import OperationFailed, Unsupported, ValidationError
from bant.platform import detect_os, has_systemd

REPO = "VAR7IANT/Bant"
API = "https://api.github.com"
ALLOWED_HOST_SUFFIXES = ("github.com", "githubusercontent.com")
MAX_API_BYTES = 4 * 1024 * 1024
MAX_SUMS_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 30 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_MEMBERS = 5000
CHANNELS = ("auto", "stable", "prerelease")
TIMER = "bant-update-check.timer"
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: str = ""

    @classmethod
    def parse(cls, text: str) -> Version | None:
        m = _SEMVER.match(text.strip())
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) or "") if m else None

    def key(self) -> tuple:
        pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre.split(".")) if self.pre else ()
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, pre)

    def __lt__(self, other: Version) -> bool:
        return self.key() < other.key()

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}" + (f"-{self.pre}" if self.pre else "")


@dataclass
class Release:
    tag: str
    version: Version
    prerelease: bool
    name: str = ""
    body: str = ""
    published: str = ""
    url: str = ""
    assets: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Network (host allow-list, size limits, redirect validation)
# ---------------------------------------------------------------------------

def allowed_url(url: str) -> bool:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    return u.scheme == "https" and any(host == s or host.endswith("." + s) for s in ALLOWED_HOST_SUFFIXES)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if not allowed_url(newurl):
            raise urllib.error.URLError(f"refusing redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, max_bytes: int, accept: str = "application/vnd.github+json") -> bytes:
    """Download with a hard size cap. Only https URLs on GitHub hosts are accepted."""
    if not allowed_url(url):
        raise OperationFailed(f"Refusing to download from {url}", hint="Bant only downloads updates from GitHub over HTTPS.")
    req = urllib.request.Request(url, headers={"User-Agent": f"bant/{__version__}", "Accept": accept,
                                               "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(_SafeRedirect)
    buf = io.BytesIO()
    try:
        with opener.open(req, timeout=20) as resp:
            while chunk := resp.read(65536):
                buf.write(chunk)
                if buf.tell() > max_bytes:
                    raise OperationFailed(f"Download from {urlparse(url).hostname} exceeds the {max_bytes // 1024} KiB limit; aborted.")
    except urllib.error.HTTPError as exc:
        raise OperationFailed(f"GitHub answered HTTP {exc.code} for {urlparse(url).path}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OperationFailed(f"Could not reach GitHub: {getattr(exc, 'reason', exc)}",
                              hint="Check the server's internet access / proxy settings and retry.") from exc
    return buf.getvalue()


def _get(ctx: Context, url: str, max_bytes: int, accept: str = "application/vnd.github+json") -> bytes:
    getter = ctx.http_get or fetch
    return getter(url, max_bytes, accept)


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------

def channel(ctx: Context) -> str:
    ch = str(ctx.config.data.get("update", {}).get("channel", "auto"))
    return ch if ch in CHANNELS else "auto"


def includes_prereleases(ctx: Context) -> bool:
    ch = channel(ctx)
    if ch == "auto":
        cur = Version.parse(__version__)
        return bool(cur and (cur.pre or cur.major == 0))  # pre-1.0 releases are all pre-releases for now
    return ch == "prerelease"


def list_releases(ctx: Context) -> list[Release]:
    try:
        data = json.loads(_get(ctx, f"{API}/repos/{REPO}/releases?per_page=30", MAX_API_BYTES))
    except json.JSONDecodeError as exc:
        raise OperationFailed("GitHub returned an unreadable release list.") from exc
    out = []
    for item in data if isinstance(data, list) else []:
        ver = Version.parse(str(item.get("tag_name", "")))
        if item.get("draft") or ver is None:
            continue
        assets = {a["name"]: a["browser_download_url"] for a in item.get("assets", []) if allowed_url(a.get("browser_download_url", ""))}
        out.append(Release(item["tag_name"], ver, bool(item.get("prerelease")), item.get("name") or "", item.get("body") or "",
                           item.get("published_at") or "", item.get("html_url") or "", assets))
    return sorted(out, key=lambda r: r.version.key(), reverse=True)


def check(ctx: Context, *, save: bool = True) -> dict[str, Any]:
    current = Version.parse(__version__)
    rels = list_releases(ctx)
    pre = includes_prereleases(ctx)
    candidates = [r for r in rels if pre or not r.prerelease]
    latest = candidates[0] if candidates else None
    available = bool(latest and current and current < latest.version)
    info = {
        "current": __version__, "channel": channel(ctx), "checked_at": int(ctx.clock()),
        "latest": str(latest.version) if latest else None, "tag": latest.tag if latest else None,
        "prerelease": latest.prerelease if latest else None, "available": available,
        "url": latest.url if latest else None, "notes": (latest.body or "")[:1500] if latest else "",
    }
    if save and ctx.is_root and not ctx.dry_run:
        ctx.state.update(lambda d: d.__setitem__("update", {**d.get("update", {}), **{k: v for k, v in info.items() if k != "notes"}}))
    return info


def cached(ctx: Context) -> dict[str, Any]:
    """Last known check result (no network)."""
    return ctx.state.get("update", default={}) or {}


# ---------------------------------------------------------------------------
# Fetching and verifying the artifact
# ---------------------------------------------------------------------------

def parse_sums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$", line.strip())
        if m:
            out[m.group(2)] = m.group(1).lower()
    return out


def tag_commit(ctx: Context, tag: str) -> str:
    ref = json.loads(_get(ctx, f"{API}/repos/{REPO}/git/ref/tags/{tag}", MAX_API_BYTES))
    obj = ref.get("object", {})
    if obj.get("type") == "tag":  # annotated tag -> dereference
        obj = json.loads(_get(ctx, f"{API}/repos/{REPO}/git/tags/{obj['sha']}", MAX_API_BYTES)).get("object", {})
    sha = str(obj.get("sha", ""))
    if obj.get("type") != "commit" or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise OperationFailed(f"Could not resolve tag {tag} to a commit.")
    return sha


def archive_commit(data: bytes) -> str:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        return str(tf.pax_headers.get("comment", "")).strip()


def acquire(ctx: Context, rel: Release) -> tuple[bytes, str]:
    name = f"bant-{rel.version}.tar.gz"
    if name in rel.assets and "SHA256SUMS" in rel.assets:
        expected = parse_sums(_get(ctx, rel.assets["SHA256SUMS"], MAX_SUMS_BYTES, "application/octet-stream").decode("utf-8", "replace")).get(name)
        if not expected:
            raise OperationFailed(f"SHA256SUMS of {rel.tag} has no entry for {name}; refusing to install.")
        data = _get(ctx, rel.assets[name], MAX_ARCHIVE_BYTES, "application/octet-stream")
        if hashlib.sha256(data).hexdigest() != expected:
            raise OperationFailed(f"Checksum mismatch for {name}: the download does not match SHA256SUMS. Nothing was installed.")
        return data, f"release asset {name}, SHA-256 verified"
    commit = tag_commit(ctx, rel.tag)
    data = _get(ctx, f"https://codeload.github.com/{REPO}/tar.gz/refs/tags/{rel.tag}", MAX_ARCHIVE_BYTES, "application/octet-stream")
    try:
        embedded = archive_commit(data)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise OperationFailed("The downloaded archive is not a valid tar.gz file.") from exc
    if embedded != commit:
        raise OperationFailed(f"Source archive commit ({embedded or 'none'}) does not match tag {rel.tag} ({commit[:12]}). Nothing was installed.")
    return data, f"source archive of {rel.tag}, commit {commit[:12]} matches the tag"


def safe_extract(data: bytes, dest: Path) -> Path:
    """Extract a release tarball into `dest` rejecting anything unusual. Returns the single top-level directory."""
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise OperationFailed("The downloaded archive is not a valid tar.gz file.") from exc
    with tf:
        members = tf.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise OperationFailed("The archive is empty or has an implausible number of entries.")
        tops = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
        total = 0
        for m in members:
            parts = Path(m.name).parts
            if m.name.startswith("/") or ".." in parts or not parts:
                raise OperationFailed(f"Unsafe path in archive: {m.name!r}")
            if not (m.isfile() or m.isdir()):
                raise OperationFailed(f"Archive contains a link or special file ({m.name!r}); refusing to extract.")
            total += m.size
            if total > MAX_EXTRACTED_BYTES:
                raise OperationFailed("The archive expands to an implausible size.")
        if len(tops) != 1:
            raise OperationFailed("The archive must contain exactly one top-level directory.")
        for m in members:
            target = dest / m.name
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                raise OperationFailed(f"Cannot read {m.name!r} from the archive.")
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)
    return dest / next(iter(tops))


def source_version(root: Path) -> str | None:
    """Version declared by a source tree (read as text; the code is not executed)."""
    try:
        text = (root / "bant" / "__init__.py").read_text()
    except OSError:
        return None
    m = re.search(r'^__version__ = "([^"]+)"', text, re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Installing / rolling back
# ---------------------------------------------------------------------------

def _lib(ctx: Context) -> Path:
    return ctx.paths.install_dir / "lib"


def _prev(ctx: Context) -> Path:
    return ctx.paths.install_dir / "lib.prev"


def installed_version(ctx: Context) -> str | None:
    return source_version(_lib(ctx))


def _preload() -> None:
    """Import every Bant module now: the program directory is about to be replaced, and a lazy import
    afterwards would mix old and new code."""
    import importlib
    import pkgutil

    import bant

    for mod in pkgutil.walk_packages(bant.__path__, "bant."):
        importlib.import_module(mod.name)


def _swap_in(ctx: Context, source: Path) -> None:
    lib = _lib(ctx)
    tmp, old = lib.with_name("lib.restoring"), lib.with_name("lib.failed")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(source, tmp)
    shutil.rmtree(old, ignore_errors=True)
    if lib.exists():
        os.rename(lib, old)
    os.rename(tmp, lib)
    shutil.rmtree(old, ignore_errors=True)


def apply(ctx: Context, version: str | None = None, *, allow_downgrade: bool = False) -> dict[str, Any]:
    ctx.require_root("Updating Bant")
    from bant.core import backups
    from bant.core.rollback import TxManager

    if not _lib(ctx).is_dir():
        raise Unsupported("This Bant was not installed with install.sh (no /opt/bant/lib).",
                          hint="Update a git checkout with `git pull && sudo bash install.sh`.")
    if ctx.paths.root == Path("/") and not has_systemd(ctx):
        raise Unsupported("systemd is required.")
    current = Version.parse(installed_version(ctx) or __version__)
    rels = list_releases(ctx)
    if version:
        want = Version.parse(version)
        if want is None:
            raise ValidationError(f"Invalid version: {version!r}", hint="Use a release number such as 0.2.0.")
        rel = next((r for r in rels if r.version == want), None)
        if rel is None:
            raise OperationFailed(f"Release {want} was not found on GitHub.")
    else:
        pre = includes_prereleases(ctx)
        cands = [r for r in rels if pre or not r.prerelease]
        rel = cands[0] if cands else None
        if rel is None:
            raise OperationFailed("No release found for your update channel.", hint="See `bant self-update channel`.")
    if current and not (current < rel.version):
        if rel.version == current:
            return {"updated": False, "current": str(current), "message": f"Already up to date ({current})."}
        if not allow_downgrade:
            raise OperationFailed(f"{rel.version} is older than the installed {current}.", hint="Add --allow-downgrade if you really want that.")
    if ctx.dry_run:
        ctx.planned += [f"download and verify Bant {rel.version} ({rel.tag})", "back up configuration", "keep the current version as lib.prev",
                        "run the new release's install.sh --no-setup", "verify the installed version"]
        return {"updated": False, "dry_run": True, "target": str(rel.version)}

    with ctx.lock():
        if TxManager(ctx).pending():
            raise OperationFailed("An SSH change is waiting for confirmation.", hint="Run `bant ssh cf` or `bant ssh rollback` first.")
        data, verified_by = acquire(ctx, rel)
        stage = ctx.paths.state_dir / "update" / str(rel.version)
        shutil.rmtree(stage, ignore_errors=True)
        try:
            root = safe_extract(data, stage)
            declared = source_version(root)
            if declared != str(rel.version):
                raise OperationFailed(f"The archive declares version {declared!r}, expected {rel.version}. Nothing was installed.")
            installer = root / "install.sh"
            if not installer.is_file() or not ctx.run(["bash", "-n", str(installer)]).ok:
                raise OperationFailed("The release has no valid install.sh. Nothing was installed.")
            _preload()
            backup = backups.create(ctx, note=f"pre-update {current} -> {rel.version}")
            shutil.rmtree(_prev(ctx), ignore_errors=True)
            shutil.copytree(_lib(ctx), _prev(ctx))
            argv = ["env"] + ([f"DESTDIR={ctx.paths.root}"] if ctx.paths.root != Path("/") else [])
            argv += ["bash", str(installer), "--yes", "--no-setup"]
            if not detect_os(ctx).supported:
                argv.append("--force-unsupported")
            res = ctx.run_mut(argv, timeout=600)
            problem = None
            if not res.ok:
                problem = f"the installer failed: {res.output[-300:]}"
            elif installed_version(ctx) != str(rel.version):
                problem = f"installed version is {installed_version(ctx)}, expected {rel.version}"
            elif ctx.paths.root == Path("/"):
                smoke = ctx.run([str(ctx.paths.launcher), "version", "--json"], timeout=30)
                if not smoke.ok or f'"{rel.version}"' not in smoke.stdout:
                    problem = f"the new `bant` command does not start correctly: {smoke.output[-200:]}"
            if problem:
                _swap_in(ctx, _prev(ctx))
                ctx.audit("selfupdate.failed", level="error", target=str(rel.version), error=problem)
                raise OperationFailed(f"Update to {rel.version} failed ({problem}); the previous version was restored.")
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        ctx.state.update(lambda d: d.setdefault("update", {}).update(
            {"previous": str(current), "current": str(rel.version), "applied_at": int(ctx.clock()), "available": False}))
        ctx.audit("selfupdate.applied", previous=str(current), current=str(rel.version), verified=verified_by, backup=backup["id"])
    return {"updated": True, "previous": str(current), "current": str(rel.version), "verified": verified_by, "backup": backup["id"],
            "tag": rel.tag}


def rollback(ctx: Context) -> dict[str, Any]:
    """Swap back to the previous program version (calling it again swaps forward)."""
    ctx.require_root("Rolling back Bant")
    prev = _prev(ctx)
    if not prev.is_dir():
        raise OperationFailed("There is no previous version to roll back to.")
    with ctx.lock():
        before, target = installed_version(ctx), source_version(prev)
        lib, swap = _lib(ctx), _lib(ctx).with_name("lib.swap")
        shutil.rmtree(swap, ignore_errors=True)
        os.rename(lib, swap)
        os.rename(prev, lib)
        os.rename(swap, prev)
        ctx.state.update(lambda d: d.setdefault("update", {}).update({"current": target, "previous": before, "available": None}))
        ctx.audit("selfupdate.rollback", frm=before, to=target)
    return {"from": before, "to": target}


# ---------------------------------------------------------------------------
# Settings: daily check timer, channel
# ---------------------------------------------------------------------------

def notify_enabled(ctx: Context) -> bool:
    return ctx.run(["systemctl", "is-enabled", "--quiet", TIMER]).ok


def set_notify(ctx: Context, enable: bool) -> str:
    ctx.require_root("Changing the update check timer")
    if not (ctx.paths.systemd_system / TIMER).exists():
        raise Unsupported(f"{TIMER} is not installed.", hint="Re-run install.sh from a current release.")
    res = ctx.run_mut(["systemctl", "enable", "--now", TIMER] if enable else ["systemctl", "disable", "--now", TIMER])
    if not res.ok:
        raise OperationFailed(f"systemctl failed: {res.output}")
    ctx.audit("selfupdate.notify", enabled=enable)
    return "Daily update check enabled (it only checks; it never installs)." if enable else "Daily update check disabled."


def set_channel(ctx: Context, ch: str) -> str:
    ctx.require_root("Changing the update channel")
    if ch not in CHANNELS:
        raise ValidationError(f"Unknown channel {ch!r}", hint="Use: " + ", ".join(CHANNELS))
    ctx.config.set("update", "channel", ch)
    if not ctx.dry_run:
        ctx.config.save()
        ctx.audit("selfupdate.channel", channel=ch)
    return f"Update channel set to {ch}."


def status(ctx: Context) -> dict[str, Any]:
    c = cached(ctx)
    prev = source_version(_prev(ctx)) if _prev(ctx).is_dir() else None
    return {"current": installed_version(ctx) or __version__, "channel": channel(ctx), "last_checked": c.get("checked_at"),
            "latest": c.get("latest"), "available": bool(c.get("available")), "daily_check": notify_enabled(ctx),
            "previous_version": prev, "last_error": None}

