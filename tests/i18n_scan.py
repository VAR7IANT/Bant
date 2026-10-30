"""Find every human-readable message template in Bant's source (used by the i18n completeness test).

A "template" is a string literal or f-string with each `{expr}` replaced by `{}`. Only strings that look
like messages are returned: they contain at least two words made of letters. Strings in contexts that are
clearly not user-facing (docstrings, command argv, regexes, audit event names, logging) are skipped.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = ["bant/cli.py", "bant/presenters.py", "bant/ui.py", "bant/tui/app.py", "bant/tui/dashboard.py", "bant/tui/menus.py",
           "bant/config.py", "bant/context.py", "bant/platform.py", "bant/ports.py"] + \
          [f"bant/core/{p.name}" for p in sorted((ROOT / "bant/core").glob("*.py")) if p.name != "__init__.py"] + \
          ["bant/utils/fsutil.py", "bant/utils/validation.py", "bant/utils/tomlio.py"]

SKIP_CALLS = {"run", "run_mut", "which", "audit", "write", "compile", "match", "search", "sub", "fullmatch", "findall", "getattr",
              "setattr", "hasattr", "isinstance", "get", "pop", "setdefault", "startswith", "endswith", "split", "join", "replace",
              "format", "open", "read_text", "write_text", "mkdir", "Path", "str", "int", "dir", "p", "glob", "iterdir", "environ",
              "ArgumentParser", "add_argument", "set_defaults", "Template", "dumps", "loads", "parse_sshd_T", "_scalar", "_arm",
              "update", "lstrip", "strip", "rstrip", "removeprefix", "index", "count", "rjust", "ljust", "center", "encode", "decode",
              "_step_key", "register", "new_id", "check_id", "DoctorCheck_", "Popen", "environ_get", "_flag_value", "locale_hint"}
WORDS = re.compile(r"[A-Za-z]{2,}")


def _template(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value).replace("{", "{{").replace("}", "}}"))
            else:
                out.append("{}")
        return "".join(out)
    return None


UI_MODULES = {"bant/cli.py", "bant/presenters.py", "bant/ui.py", "bant/tui/app.py", "bant/tui/dashboard.py", "bant/tui/menus.py"}
# lower-case single words that are shown to the user as values (everything else lower-case single-token is an identifier)
KNOWN_SINGLE_WORDS = {"yes", "no", "public", "loopback", "specific", "manage", "none", "never", "unknown", "permanent", "random", "active",
                      "inactive", "installed", "stable", "prerelease", "auto", "restored", "nothing", "sshd", "failed", "done", "pending",
                      "skipped", "baseline", "backup", "fail2ban", "firewall", "ssh", "ssh-migration", "update-check", "critical", "high",
                      "medium", "low", "info", "healthy", "attention", "system", "config", "backups", "permissions", "rollback", "updates",
                      "audit", "logs", "kernel", "service", "observe", "user", "flag",
                      "environment", "unset"}


def _messagey(t: str, rel: str) -> bool:
    plain = re.sub(r"\{[^}]*\}", " ", t).strip()
    if not plain or plain.startswith(("#", "[", "<")) or "\n" in t.strip() or "$(" in t or "||" in t or "://" in t and " " not in t:
        return False
    tokens = [w for w in plain.split() if re.fullmatch(r"[(A-Za-z][A-Za-z'/.,:;()+-]*", w)]
    if len(tokens) >= 2:
        return True
    if plain in KNOWN_SINGLE_WORDS:
        return True
    # a single capitalised word/label in a UI module ("Back", "Version", "Enabled")
    return rel in UI_MODULES and bool(re.fullmatch(r"[A-Z][A-Za-z0-9/-]+", plain))


def scan(modules: list[str] | None = None) -> dict[str, list[str]]:
    """template -> ['file:line', ...]"""
    found: dict[str, list[str]] = {}
    for rel in modules or MODULES:
        path = ROOT / rel
        if not path.exists():
            continue
        tree = ast.parse(path.read_text())
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                    docstrings.add(first.value)
        for node in ast.walk(tree):
            if node in docstrings or not isinstance(node, (ast.Constant, ast.JoinedStr)):
                continue
            if isinstance(node, ast.Constant) and not isinstance(node.value, str):
                continue
            if isinstance(parents.get(node), ast.JoinedStr):
                continue  # pieces of an f-string are handled via the f-string itself
            t = _template(node)
            if t is None or not _messagey(t, rel):
                continue
            # skip strings that are arguments to non-UI calls, subscripts keys, comparisons, etc.
            parent = parents.get(node)
            skip = False
            cur: ast.AST | None = parent
            depth = 0
            while cur is not None and depth < 4:
                if isinstance(cur, ast.Call):
                    fn = cur.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
                    if name in SKIP_CALLS:
                        skip = True
                    break
                if isinstance(cur, (ast.Compare, ast.Subscript)) or (isinstance(cur, ast.Dict) and node in cur.keys):
                    skip = True
                    break
                cur = parents.get(cur)
                depth += 1
            if isinstance(parent, ast.keyword) and parent.arg in ("dest", "metavar", "prog", "choices", "default", "type", "evidence"):
                skip = True
            if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id == "Finding" \
                    and node in parent.args and parent.args.index(node) in (0, 1, 3, 7):
                skip = True  # id, severity, evidence (raw technical data) and fix command are not translated
            if skip:
                continue
            found.setdefault(t, []).append(f"{rel}:{node.lineno}")
    return found


def shape(template: str) -> str:
    """Normalise placeholders so catalog keys (named) compare equal to scanned templates (anonymous)."""
    return re.sub(r"\{[^{}]*\}", "{}", template)


if __name__ == "__main__":
    items = scan()
    print(len(items), "message templates")
    for t, locs in sorted(items.items(), key=lambda kv: kv[1][0]):
        print(f"{locs[0]:38} {t!r}")
