"""A fake GitHub for updater tests: serves releases, assets and tag archives built from this checkout."""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import time
from pathlib import Path

from bant.errors import OperationFailed

ROOT = Path(__file__).resolve().parents[1]
REPO = "VAR7IANT/Bant"


def project_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / line for line in out.splitlines() if (ROOT / line).is_file()]


def build_tarball(version: str, commit: str, *, mutate=None, extra_members=()) -> bytes:
    """tar.gz of this project as release `version`, top dir Bant-<version>/, GitHub-style pax comment = commit."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
        for path in project_files():
            rel = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            if rel == "bant/__init__.py":
                data = re.sub(rb'__version__ = "[^"]+"', f'__version__ = "{version}"'.encode(), data)
            if mutate:
                data = mutate(rel, data)
            info = tarfile.TarInfo(f"Bant-{version}/{rel}")
            info.size = len(data)
            info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.mtime = int(time.time())
            tf.addfile(info, io.BytesIO(data))
        for info, payload in extra_members:
            tf.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buf.getvalue()


class FakeGitHub:
    def __init__(self):
        self.releases: list[dict] = []
        self.files: dict[str, bytes] = {}
        self.json: dict[str, object] = {}
        self.calls: list[str] = []
        self.offline = False

    def add_release(self, version: str, *, prerelease=False, draft=False, assets=False, body="notes", tag=None,
                    tarball: bytes | None = None, commit: str | None = None, sums: str | None = None, asset_bytes: bytes | None = None):
        tag = tag or f"v{version}"
        commit = commit or hashlib.sha1(tag.encode()).hexdigest()  # noqa: S324 - fake commit id
        tarball = tarball if tarball is not None else build_tarball(version, commit)
        item = {"tag_name": tag, "name": f"Bant {version}", "body": body, "prerelease": prerelease, "draft": draft,
                "published_at": "2026-10-30T00:00:00Z", "html_url": f"https://github.com/{REPO}/releases/tag/{tag}", "assets": []}
        if assets:
            name = f"bant-{version}.tar.gz"
            payload = asset_bytes if asset_bytes is not None else tarball
            base = f"https://github.com/{REPO}/releases/download/{tag}"
            self.files[f"{base}/{name}"] = payload
            sums_text = sums if sums is not None else f"{hashlib.sha256(tarball).hexdigest()}  {name}\n"
            self.files[f"{base}/SHA256SUMS"] = sums_text.encode()
            item["assets"] = [{"name": name, "browser_download_url": f"{base}/{name}"},
                              {"name": "SHA256SUMS", "browser_download_url": f"{base}/SHA256SUMS"}]
        else:
            self.files[f"https://codeload.github.com/{REPO}/tar.gz/refs/tags/{tag}"] = tarball
        tag_obj = hashlib.sha1(b"tagobj" + tag.encode()).hexdigest()  # noqa: S324
        self.json[f"https://api.github.com/repos/{REPO}/git/ref/tags/{tag}"] = {"object": {"type": "tag", "sha": tag_obj}}
        self.json[f"https://api.github.com/repos/{REPO}/git/tags/{tag_obj}"] = {"object": {"type": "commit", "sha": commit}}
        self.releases.append(item)
        return commit

    def __call__(self, url: str, max_bytes: int, accept: str = "") -> bytes:
        self.calls.append(url)
        if self.offline:
            raise OperationFailed("Could not reach GitHub: simulated outage")
        if url.startswith(f"https://api.github.com/repos/{REPO}/releases"):
            return json.dumps(self.releases).encode()
        if url in self.json:
            return json.dumps(self.json[url]).encode()
        if url in self.files:
            data = self.files[url]
            if len(data) > max_bytes:
                raise OperationFailed("Download exceeds the limit; aborted.")
            return data
        raise OperationFailed(f"GitHub answered HTTP 404 for {url}")
