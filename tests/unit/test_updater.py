"""Built-in updater: version logic, verification, safe extraction, install, failure recovery, rollback."""

import io
import json
import re
import tarfile

import pytest

from bant import __version__
from bant.core import updater
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, PermissionDenied, Unsupported, ValidationError
from tests.fakegithub import FakeGitHub, build_tarball
from tests.fakes import FakeHost

INSTALLED = "0.1.0"


@pytest.fixture
def gh():
    return FakeGitHub()


def install_current(host, version=INSTALLED):
    """Lay down an 'installed' Bant (lib + launcher) in the fake root by running the real installer."""
    import subprocess
    import sys
    from pathlib import Path

    src = Path(__file__).resolve().parents[2]
    stage = host.root.parent / "installed-src"
    import shutil
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(src, stage, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache", "*.egg-info"))
    init = stage / "bant" / "__init__.py"
    init.write_text(re.sub(r'__version__ = "[^"]+"', f'__version__ = "{version}"', init.read_text()))
    res = subprocess.run(["bash", str(stage / "install.sh"), "--yes", "--no-setup"], env={"DESTDIR": str(host.root), "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert sys.executable


@pytest.fixture
def env(tmp_path, gh):
    host = FakeHost(tmp_path / "root")
    host.http_get = gh
    install_current(host)
    return host, host.make_ctx(), gh


# ---- versions / urls -------------------------------------------------------------

def test_version_ordering():
    order = ["0.1.0", "0.1.1", "0.2.0-rc.1", "0.2.0-rc.2", "0.2.0-rc.10", "0.2.0", "1.0.0"]
    parsed = [updater.Version.parse(v) for v in order]
    assert parsed == sorted(parsed, key=lambda v: v.key())
    assert updater.Version.parse("v0.1.0") == updater.Version(0, 1, 0)
    for bad in ("", "latest", "1.2", "v1.2.3.4", "1.2.x", "../1.0.0"):
        assert updater.Version.parse(bad) is None


def test_only_https_github_hosts_are_allowed():
    ok = ["https://api.github.com/repos/x", "https://codeload.github.com/a/b", "https://objects.githubusercontent.com/x",
          "https://github.com/a/b/releases/download/v1/x.tar.gz"]
    bad = ["http://api.github.com/x", "https://evil.example/x", "https://github.com.evil.example/x", "https://notgithub.com/x",
           "ftp://github.com/x", "file:///etc/passwd", "https://api.github.com.evil.io/"]
    assert all(updater.allowed_url(u) for u in ok) and not any(updater.allowed_url(u) for u in bad)
    with pytest.raises(OperationFailed, match="Refusing"):
        updater.fetch("https://evil.example/x", 10)


def test_sums_parsing():
    h = "a" * 64
    assert updater.parse_sums(f"{h}  bant-1.tar.gz\n{h.upper()} *other\njunk\n") == {"bant-1.tar.gz": h, "other": h}


# ---- check -----------------------------------------------------------------------

def test_check_reports_available_update_and_caches_it(env):
    host, ctx, gh = env
    gh.add_release("0.1.0", prerelease=True)
    gh.add_release("0.2.0", prerelease=True, body="# Notes")
    info = updater.check(ctx)
    assert info["available"] and info["latest"] == "0.2.0" and info["notes"] == "# Notes"
    assert ctx.state.get("update", "latest") == "0.2.0" and ctx.state.get("update", "available") is True


def test_check_up_to_date(env):
    host, ctx, gh = env
    gh.add_release("0.1.0", prerelease=True)
    assert not updater.check(ctx)["available"]


def test_check_ignores_drafts_and_non_semver_tags(env):
    host, ctx, gh = env
    gh.add_release("9.9.9", draft=True)
    gh.add_release("0.1.0", tag="nightly-2026-10-30")
    gh.add_release("0.1.5", prerelease=True)
    assert updater.check(ctx)["latest"] == "0.1.5"


def test_channel_stable_skips_prereleases_and_auto_includes_them_below_1_0(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    gh.add_release("0.1.9")
    assert updater.channel(ctx) == "auto" and updater.check(ctx)["latest"] == "0.2.0"
    ctx.config.set("update", "channel", "stable")
    assert updater.check(ctx)["latest"] == "0.1.9"


def test_check_without_root_does_not_write_state(tmp_path, gh):
    host = FakeHost(tmp_path / "r", euid=1000)
    host.http_get = gh
    gh.add_release("0.2.0", prerelease=True)
    ctx = host.make_ctx()
    assert updater.check(ctx)["available"]
    assert not host.paths.state_file.exists()


def test_network_failure_is_a_clear_error(env):
    host, ctx, gh = env
    gh.offline = True
    with pytest.raises(OperationFailed, match="Could not reach GitHub"):
        updater.check(ctx)


# ---- apply: success paths --------------------------------------------------------

def test_apply_from_verified_release_asset(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True, assets=True)
    (host.paths.etc_bant).mkdir(parents=True, exist_ok=True)
    host.paths.config_file.write_text('[ssh]\nport = 2222\n')
    res = updater.apply(ctx)
    assert res["updated"] and res["previous"] == "0.1.0" and res["current"] == "0.2.0" and "SHA-256 verified" in res["verified"]
    assert updater.installed_version(ctx) == "0.2.0"
    assert updater.source_version(ctx.paths.install_dir / "lib.prev") == "0.1.0", "previous version kept for rollback"
    assert host.paths.config_file.read_text() == '[ssh]\nport = 2222\n', "configuration must survive an update"
    assert ctx.paths.launcher.exists() and (ctx.paths.systemd_system / "bant-update-check.timer").exists()
    assert not (ctx.paths.state_dir / "update" / "0.2.0").exists(), "staging directory cleaned up"
    assert ctx.state.get("update", "current") == "0.2.0" and ctx.state.get("update", "previous") == "0.1.0"
    assert any(r["event"] == "selfupdate.applied" for r in ctx.audit_log.read(50))
    assert (res["backup"])


def test_apply_from_source_archive_when_release_has_no_assets(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    res = updater.apply(ctx)
    assert res["updated"] and "source archive" in res["verified"] and updater.installed_version(ctx) == "0.2.0"


def test_apply_explicit_version_and_downgrade_rules(env):
    host, ctx, gh = env
    gh.add_release("0.0.9", prerelease=True)
    gh.add_release("0.2.0", prerelease=True)
    with pytest.raises(OperationFailed, match="older"):
        updater.apply(ctx, "0.0.9")
    assert updater.installed_version(ctx) == "0.1.0"
    res = updater.apply(ctx, "0.0.9", allow_downgrade=True)
    assert res["current"] == "0.0.9"
    with pytest.raises(ValidationError):
        updater.apply(ctx, "banana")
    with pytest.raises(OperationFailed, match="not found"):
        updater.apply(ctx, "7.7.7")


def test_apply_when_already_current(env):
    host, ctx, gh = env
    gh.add_release("0.1.0", prerelease=True)
    assert updater.apply(ctx)["updated"] is False


def test_dry_run_downloads_nothing_and_changes_nothing(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    ctx.dry_run = True
    calls_before = len(gh.calls)
    res = updater.apply(ctx)
    assert res["dry_run"] and updater.installed_version(ctx) == "0.1.0"
    assert not any("codeload" in c or "releases/download" in c for c in gh.calls[calls_before:])


# ---- apply: verification failures change nothing --------------------------------------

def test_checksum_mismatch_is_refused(env):
    host, ctx, gh = env
    good = build_tarball("0.2.0", "c" * 40)
    gh.add_release("0.2.0", prerelease=True, assets=True, tarball=good, asset_bytes=good + b"tampered")
    with pytest.raises(OperationFailed, match="Checksum mismatch"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0" and not (ctx.paths.install_dir / "lib.prev").exists()


def test_missing_checksum_entry_is_refused(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True, assets=True, sums="0" * 64 + "  something-else.tar.gz\n")
    with pytest.raises(OperationFailed, match="no entry"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"


def test_source_archive_commit_must_match_the_tag(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True, tarball=build_tarball("0.2.0", "f" * 40))  # embedded commit != tag's commit
    with pytest.raises(OperationFailed, match="does not match tag"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"


def test_archive_declaring_a_different_version_is_refused(env):
    host, ctx, gh = env
    commit = "a" * 40
    gh.add_release("0.2.0", prerelease=True, commit=commit, tarball=build_tarball("0.3.5", commit))
    with pytest.raises(OperationFailed, match="declares version"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"


def test_pending_ssh_transaction_blocks_update(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    from bant.core import migration
    migration.begin(ctx, 2222)
    assert TxManager(ctx).pending()
    with pytest.raises(OperationFailed, match="waiting for confirmation"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"


def test_requires_root_and_an_install_sh_installation(tmp_path, gh):
    host = FakeHost(tmp_path / "r", euid=1000)
    host.http_get = gh
    with pytest.raises(PermissionDenied):
        updater.apply(host.make_ctx())
    host2 = FakeHost(tmp_path / "r2")
    host2.http_get = gh
    with pytest.raises(Unsupported, match="install.sh"):
        updater.apply(host2.make_ctx())


# ---- apply: failure after verification restores the old version --------------------------

def test_installer_failure_restores_previous_version(env):
    host, ctx, gh = env
    commit = "b" * 40

    def break_installer(rel, data):
        return b"#!/usr/bin/env bash\necho boom >&2\nexit 7\n" if rel == "install.sh" else data
    gh.add_release("0.2.0", prerelease=True, commit=commit, tarball=build_tarball("0.2.0", commit, mutate=break_installer))
    before = (ctx.paths.install_dir / "lib" / "bant" / "cli.py").read_bytes()
    with pytest.raises(OperationFailed, match="previous version was restored"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"
    assert (ctx.paths.install_dir / "lib" / "bant" / "cli.py").read_bytes() == before
    assert any(r["event"] == "selfupdate.failed" for r in ctx.audit_log.read(50))


def test_installer_that_installs_the_wrong_version_is_undone(env):
    host, ctx, gh = env
    commit = "d" * 40

    def noop_installer(rel, data):  # a "successful" installer that installs nothing
        return b"#!/usr/bin/env bash\nexit 0\n" if rel == "install.sh" else data
    gh.add_release("0.2.0", prerelease=True, commit=commit, tarball=build_tarball("0.2.0", commit, mutate=noop_installer))
    with pytest.raises(OperationFailed, match="expected 0.2.0"):
        updater.apply(ctx)
    assert updater.installed_version(ctx) == "0.1.0"


def test_syntax_broken_installer_is_rejected_before_anything_runs(env):
    host, ctx, gh = env
    commit = "e" * 40
    gh.add_release("0.2.0", prerelease=True, commit=commit,
                   tarball=build_tarball("0.2.0", commit, mutate=lambda rel, d: b"if then fi (" if rel == "install.sh" else d))
    with pytest.raises(OperationFailed, match="valid install.sh"):
        updater.apply(ctx)
    assert not (ctx.paths.install_dir / "lib.prev").exists()


# ---- safe extraction -------------------------------------------------------------------

def tar_with(*members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for info, payload in members:
            tf.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buf.getvalue()


def file_info(name, size=3, mode=0o644):
    i = tarfile.TarInfo(name)
    i.size, i.mode = size, mode
    return i


@pytest.mark.parametrize("name", ["../evil", "Bant-1/../../evil", "/etc/passwd"])
def test_extraction_rejects_path_traversal(tmp_path, name):
    with pytest.raises(OperationFailed, match="Unsafe path"):
        updater.safe_extract(tar_with((file_info(name), b"abc")), tmp_path / "out")
    assert not (tmp_path / "evil").exists()


def test_extraction_rejects_links_and_devices(tmp_path):
    for kind, extra in ((tarfile.SYMTYPE, "/etc/passwd"), (tarfile.LNKTYPE, "Bant-1/a"), (tarfile.CHRTYPE, ""), (tarfile.FIFOTYPE, "")):
        info = tarfile.TarInfo("Bant-1/x")
        info.type, info.linkname = kind, extra
        with pytest.raises(OperationFailed, match="link or special"):
            updater.safe_extract(tar_with((file_info("Bant-1/a"), b"abc"), (info, None)), tmp_path / f"out{kind!r}")


def test_extraction_requires_one_top_level_directory(tmp_path):
    with pytest.raises(OperationFailed, match="one top-level"):
        updater.safe_extract(tar_with((file_info("a/x"), b"abc"), (file_info("b/y"), b"abc")), tmp_path / "out")


def test_extraction_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "MAX_EXTRACTED_BYTES", 10)
    with pytest.raises(OperationFailed, match="implausible size"):
        updater.safe_extract(tar_with((file_info("Bant-1/a", size=50), b"x" * 50)), tmp_path / "out")
    with pytest.raises(OperationFailed, match="not a valid"):
        updater.safe_extract(b"not a tarball", tmp_path / "out2")


def test_extraction_normalises_permissions(tmp_path):
    root = updater.safe_extract(tar_with((file_info("Bant-1/run.sh", mode=0o4777), b"abc"), (file_info("Bant-1/data", mode=0o666), b"abc")),
                                tmp_path / "out")
    assert (root / "run.sh").stat().st_mode & 0o7777 == 0o755 and (root / "data").stat().st_mode & 0o7777 == 0o644


# ---- rollback / settings ---------------------------------------------------------------

def test_rollback_swaps_versions_and_back(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    updater.apply(ctx)
    res = updater.rollback(ctx)
    assert res == {"from": "0.2.0", "to": "0.1.0"} and updater.installed_version(ctx) == "0.1.0"
    assert updater.rollback(ctx)["to"] == "0.2.0", "a second rollback flips forward again"


def test_rollback_without_previous_version(env):
    host, ctx, gh = env
    with pytest.raises(OperationFailed, match="no previous version"):
        updater.rollback(ctx)


def test_notify_and_channel_settings(env):
    host, ctx, gh = env
    assert "enabled" in updater.set_notify(ctx, True) and host.called("systemctl enable --now bant-update-check.timer")
    assert "disabled" in updater.set_notify(ctx, False)
    assert updater.set_channel(ctx, "stable").endswith("stable.") and host.make_ctx().config.data["update"]["channel"] == "stable"
    with pytest.raises(ValidationError):
        updater.set_channel(ctx, "nightly")


def test_notify_without_unit_is_unsupported(tmp_path):
    ctx = FakeHost(tmp_path / "r").make_ctx()
    with pytest.raises(Unsupported):
        updater.set_notify(ctx, True)


def test_status_reports_state(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    updater.check(ctx)
    st = updater.status(host.make_ctx())
    assert st["current"] == "0.1.0" and st["latest"] == "0.2.0" and st["available"] and st["previous_version"] is None


# ---- through the CLI ---------------------------------------------------------------------

def run_cli(host, *argv, stdin=None):
    from bant.cli import main
    from bant.ui import UI
    out = io.StringIO()
    ui = UI(stream=out, color=False, force_plain=True, input_fn=(lambda p="": stdin.pop(0)) if stdin else input)
    return main(list(argv), ctx=host.make_ctx(), ui=ui), out.getvalue()


def test_cli_check_and_json(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    rc, out = run_cli(host, "self-update", "check", "--json")
    data = json.loads(out)
    assert rc == 0 and data["available"] and data["latest"] == "0.2.0"
    rc, out = run_cli(host, "self-update", "check")
    assert "Update available: 0.2.0" in out


def test_cli_quiet_check_is_silent_when_up_to_date(env):
    host, ctx, gh = env
    gh.add_release("0.1.0", prerelease=True)
    assert run_cli(host, "self-update", "check", "--quiet") == (0, "")


def test_cli_apply_end_to_end(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True, assets=True)
    rc, out = run_cli(host, "self-update", "apply", "--yes")
    assert rc == 0 and "Updated Bant 0.1.0 -> 0.2.0" in out and "Start `bant` again" in out
    assert updater.installed_version(host.make_ctx()) == "0.2.0"
    rc, out = run_cli(host, "self-update", "rollback", "--yes")
    assert rc == 0 and updater.installed_version(host.make_ctx()) == "0.1.0"


def test_cli_default_command_checks_then_offers_to_install(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    rc, out = run_cli(host, "self-update", "--yes")
    assert rc == 0 and updater.installed_version(host.make_ctx()) == "0.2.0"


def test_cli_apply_requires_root(tmp_path, gh):
    host = FakeHost(tmp_path / "r", euid=1000)
    host.http_get = gh
    gh.add_release("0.2.0", prerelease=True)
    rc, out = run_cli(host, "self-update", "apply", "--yes")
    assert rc == 3 and "requires root" in out
    rc, out = run_cli(host, "self-update")
    assert rc == 0 and "Update available" in out and "sudo" in out


def test_cli_network_error_exit_code(env):
    host, ctx, gh = env
    gh.offline = True
    rc, out = run_cli(host, "self-update", "check")
    assert rc == 1 and "Could not reach GitHub" in out


def test_status_and_dashboard_show_cached_update_without_network(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    updater.check(ctx)
    gh.offline = True  # status must not touch the network
    rc, out = run_cli(host, "status")
    assert rc == 0 and "0.2.0 available" in out
    from bant.tui import dashboard
    from bant.ui import UI
    buf = io.StringIO()
    dashboard.draw(host.make_ctx(), UI(stream=buf, color=False, force_plain=True))
    assert "0.2.0 is available" in buf.getvalue()


def test_installed_launcher_reports_new_version_after_update(env):
    host, ctx, gh = env
    gh.add_release("0.2.0", prerelease=True)
    updater.apply(ctx)
    import subprocess
    import sys
    lib = ctx.paths.install_dir / "lib"
    out = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(lib)!r}); from bant.cli import main; sys.exit(main())", "version"],
                         capture_output=True, text=True, cwd="/")
    assert out.stdout.strip() == "bant 0.2.0" and __version__
