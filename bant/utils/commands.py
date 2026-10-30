"""Subprocess execution. Everything runs as an argv list with shell=False."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class CmdResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()

    def lines(self) -> list[str]:
        return self.stdout.splitlines()


@dataclass
class Runner:
    """Executes external programs with a sanitised environment."""

    default_timeout: float = 30.0
    history: list[list[str]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        input: str | None = None,
    ) -> CmdResult:
        argv = [str(a) for a in argv]
        env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}
        try:
            proc = subprocess.run(
                argv,
                input=input,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout or self.default_timeout,
                env=env,
                stdin=subprocess.DEVNULL if input is None else None,
                check=False,
            )
        except FileNotFoundError:
            return CmdResult(argv, 127, "", f"{argv[0]}: command not found")
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return CmdResult(argv, 124, out, f"{argv[0]}: timed out after {timeout or self.default_timeout}s")
        except OSError as exc:
            return CmdResult(argv, 126, "", f"{argv[0]}: {exc}")
        return CmdResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "")

    def which(self, name: str) -> str | None:
        import shutil

        return shutil.which(name, path=SAFE_PATH)
