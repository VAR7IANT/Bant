"""Documentation must not drift from the CLI."""

import argparse
from pathlib import Path

from bant.cli import build_parser

DOCS = Path(__file__).resolve().parents[2] / "docs"


def commands(parser: argparse.ArgumentParser, prefix=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                if name.startswith("_"):
                    continue
                yield prefix + (name,)
                yield from commands(sub, prefix + (name,))


def test_every_cli_command_is_documented():
    text = (DOCS / "CLI.md").read_text()
    missing = []
    for path in commands(build_parser()):
        head = " ".join(("bant",) + path[:1])
        if len(path) == 1 and head not in text:
            missing.append(head)
        if len(path) == 2 and path[1] not in text:
            missing.append(" ".join(path))
    assert not missing, f"undocumented commands: {missing}"


def test_required_docs_exist():
    for name in ("INSTALL.md", "CLI.md", "SECURITY.md", "RECOVERY.md", "ARCHITECTURE.md", "TESTING.md"):
        assert (DOCS / name).stat().st_size > 500
