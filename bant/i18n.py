"""Interface language: English (source text), Simplified Chinese (zh-CN) and Traditional Chinese (zh-TW).

Design: the program's messages stay plain English strings / f-strings. They are translated at the
*output boundary* (UI methods, error printing) by `tr()`:

  1. exact lookup in the active language's catalog (bant/locales/zh_cn.py or zh_tw.py);
  2. otherwise the catalog's templates (keys containing `{name}` placeholders) are matched against the
     already-formatted text, the captured values are translated recursively, and substituted into the
     Chinese template;
  3. otherwise the text is returned unchanged (English), so a missing translation can never break
     output - tests make sure none are missing.

`--json` output is always English so that machine-readable output is stable.
"""

from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass
from pathlib import Path

LANGS = {"zh-CN": "简体中文", "zh-TW": "繁體中文", "en": "English"}
DEFAULT = "en"  # used when neither a saved choice nor the system locale names a supported language
LEGACY = {"zh": "zh-TW"}  # Bant <= 0.1.2 had a single Chinese option, which was Traditional Chinese
_ALIASES = {
    "en": "en", "english": "en", "en-us": "en", "en-gb": "en",
    "zh-cn": "zh-CN", "zh-hans": "zh-CN", "zh-sg": "zh-CN", "zh-hans-cn": "zh-CN", "cn": "zh-CN", "简体中文": "zh-CN", "简体": "zh-CN",
    "zh-tw": "zh-TW", "zh-hant": "zh-TW", "zh-hk": "zh-TW", "zh-mo": "zh-TW", "zh-hant-tw": "zh-TW", "tw": "zh-TW",
    "繁體中文": "zh-TW", "繁體": "zh-TW", "繁体中文": "zh-TW",
    "zh": "zh-TW",
}


def normalize(value: str | None) -> str | None:
    """'zh_CN.UTF-8', 'zh-cn', 'zh-Hans' -> 'zh-CN'; legacy 'zh' -> 'zh-TW'; None if not a supported language."""
    if not value:
        return None
    v = str(value).strip().split(".")[0].split("@")[0].replace("_", "-").lower()
    return _ALIASES.get(v)

_COMMANDISH = re.compile(r"^(sudo|chmod|apt|apt-get|systemctl|journalctl|ssh|git)\s")
_CJK = re.compile(r"[\u3000-\u9fff\uff00-\uffef]")
_lang = DEFAULT
_recording: set[str] | None = None
_compiled: dict[str, tuple[dict[str, str], list[_Template]]] = {}
_cache: dict[str, str] = {}


@dataclass
class _Template:
    regex: re.Pattern[str]
    names: list[str]
    zh: str
    anchor: str  # longest literal fragment; cheap pre-filter before running the regex
    weight: int  # total literal characters; more specific templates are tried first
    prefix: bool = False  # key ends in whitespace: matches the start of a longer text, the rest is translated separately


def set_language(code: str) -> None:
    global _lang
    _lang = normalize(code) or DEFAULT
    _cache.clear()


def apply(code: str, stream) -> str:
    """Switch the live language for output on `stream`; Chinese falls back to English on a non-UTF-8 terminal."""
    from bant.ui import stream_shows_cjk

    code = normalize(code) or DEFAULT
    set_language(code if code == "en" or stream_shows_cjk(stream) else "en")
    return _lang


def catalog(code: str | None = None) -> dict[str, str]:
    """The message catalog of a Chinese language (English needs none)."""
    code = normalize(code) or _lang
    if code == "zh-CN":
        from bant.locales.zh_cn import ZH as CN
        return CN
    from bant.locales.zh_tw import ZH as TW
    return TW


def language() -> str:
    return _lang


def start_recording() -> None:
    global _recording
    _recording = set()


def stop_recording() -> set[str]:
    global _recording
    out, _recording = (_recording or set()), None
    return out


def _load() -> tuple[dict[str, str], list[_Template]]:
    hit = _compiled.get(_lang)
    if hit is not None:
        return hit
    ZH = catalog(_lang)
    exact: dict[str, str] = {}
    templates: list[_Template] = []
    fmt = string.Formatter()
    for key, zh in ZH.items():
        is_prefix = key != key.rstrip()
        parts = list(fmt.parse(key))
        counter = iter(range(100))
        # anonymous "{}" placeholders (as emitted by the scanner) are numbered {0}, {1}, ... in order of appearance
        names = [(str(next(counter)) if name == "" else name) for _, name, _, _ in parts if name is not None]
        if not names and not is_prefix:
            exact[key] = zh
            continue
        pattern = "".join(re.escape(lit) + ("(.+?)" if name is not None else "") for lit, name, _, _ in parts)
        literals = [lit for lit, _, _, _ in parts]
        anchor = max(literals, key=len).strip() if literals else ""
        templates.append(_Template(re.compile(f"^{pattern}" + ("" if is_prefix else "$"), re.S), names, zh, anchor,
                                   sum(len(x) for x in literals), is_prefix))
    templates.sort(key=lambda t: -t.weight)
    _compiled[_lang] = (exact, templates)
    return _compiled[_lang]


def tr(text: object, *, _depth: int = 0, record: bool = True) -> str:
    """Translate one message for display. Never raises; unknown text is returned unchanged."""
    s = text if isinstance(text, str) else str(text)
    if _lang == "en" or not s.strip():
        return s
    hit = _cache.get(s)
    if hit is not None:
        return hit
    exact, templates = _load()
    out = _lookup(s, exact, templates, _depth)
    if out is None:
        if _recording is not None and record and re.search(r"[A-Za-z]{3,}", s) and not _CJK.search(s) and not _COMMANDISH.match(s.strip()):
            _recording.add(s)
        out = s
    _cache[s] = out
    return out


def _lookup(s: str, exact: dict[str, str], templates: list[_Template], depth: int) -> str | None:
    if s in exact:
        return exact[s]
    stripped = s.strip()
    if stripped != s and stripped in exact:  # tolerate padding/indentation added by callers
        lead, trail = s[: len(s) - len(s.lstrip())], s[len(s.rstrip()):]
        return lead + exact[stripped] + trail
    if "\n" in stripped and depth == 0:
        # A multi-line message is translated line by line first: otherwise the last placeholder of a
        # template that matches the first line would swallow every following line as its "value".
        lines = s.split("\n")
        done = [_translate_piece(line, depth) for line in lines]
        if all(a != b for a, b in zip(lines, done, strict=True) if a.strip() and re.search(r"[A-Za-z]{3,}", a)):
            return "\n".join(done)
    for t in templates:
        if t.anchor and t.anchor not in s:
            continue
        m = t.regex.match(s)
        if not m:
            continue
        args: list[str] = []
        kwargs: dict[str, str] = {}
        for name, val in zip(t.names, m.groups(), strict=True):
            shown = tr(val, _depth=depth + 1, record=False) if depth < 2 else val
            if name.isdigit():
                while len(args) <= int(name):
                    args.append("")
                args[int(name)] = shown
            else:
                kwargs[name] = shown
        try:
            head = t.zh.format(*args, **kwargs)
        except (KeyError, IndexError, ValueError):
            return None
        if t.prefix:
            rest = s[m.end():]
            return head + (tr(rest, _depth=depth + 1, record=False) if rest else "")
        return head
    return _split_lookup(s, exact, templates, depth)


_SENTENCE = re.compile(r"(?<=[.!?;])\s+(?=[A-Z`'\"(\[])")


def _split_lookup(s: str, exact: dict[str, str], templates: list[_Template], depth: int) -> str | None:
    """Multi-line / multi-sentence messages: translate each line, then each sentence, independently."""
    if depth > 1:
        return None
    core = s.strip()
    if core != s and core:  # callers often add indentation ("  " + message)
        out = tr(core, _depth=depth + 1, record=False)
        if out != core:
            return s[: len(s) - len(s.lstrip())] + out + s[len(s.rstrip()):]
    if "\n" in s:
        lines = s.split("\n")
        done = [_translate_piece(line, depth) for line in lines]
        return "\n".join(done) if any(a != b for a, b in zip(lines, done, strict=True)) else None
    parts = _SENTENCE.split(s)
    if len(parts) > 1:
        done = [_translate_piece(p, depth) for p in parts]
        if all(a == b for a, b in zip(parts, done, strict=True)):
            return None
        out = done[0]
        for prev_src, prev, src, cur in zip(parts, done, parts[1:], done[1:], strict=False):
            out += ("" if (prev != prev_src and cur != src) else " ") + cur
        return out
    return None


def _translate_piece(piece: str, depth: int) -> str:
    if not piece.strip():
        return piece
    out = tr(piece, _depth=depth + 1, record=False)          # keys may carry their own indentation ("  1. Open ...")
    if out != piece:
        return out
    lead = piece[: len(piece) - len(piece.lstrip())]
    core = piece.strip()
    out = tr(core, _depth=depth + 1, record=False)
    return lead + out if out != core else piece
    return None


# ---------------------------------------------------------------------------
# Choosing and remembering the language
# ---------------------------------------------------------------------------

def locale_hint(env: dict[str, str] | None = None) -> str | None:
    """The language the system locale asks for: zh_CN/zh_SG/zh_Hans -> zh-CN, zh_TW/zh_HK/zh_MO/zh_Hant -> zh-TW."""
    env = os.environ if env is None else env
    for var in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        val = (env.get(var) or "").split(":")[0].split(".")[0].replace("_", "-").lower()
        if val.startswith("zh"):
            return "zh-TW" if any(t in val for t in ("-tw", "-hk", "-mo", "hant")) else "zh-CN"
        if val.startswith("en"):
            return "en"
    return None


def user_pref_files(home_candidates: list[Path]) -> list[Path]:
    return [h / ".config" / "bant" / "language" for h in home_candidates]


def read_user_pref(home_candidates: list[Path]) -> str | None:
    for path in user_pref_files(home_candidates):
        try:
            code = path.read_text().strip()
        except OSError:
            continue
        if normalize(code):
            return normalize(code)
    return None


def write_user_pref(home: Path, code: str) -> Path:
    path = home / ".config" / "bant" / "language"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code + "\n")
    return path


def resolve(ctx, explicit: str | None = None) -> tuple[str | None, str]:
    """(language, source). Language is None when the user has never chosen one.

    Order: explicit flag/env -> personal preference file -> system config -> (None).
    """
    if normalize(explicit):
        return normalize(explicit), "flag"
    env = normalize(os.environ.get("BANT_LANG", ""))
    if env:
        return env, "environment"
    pref = read_user_pref(ctx.user_homes())
    if pref:
        return pref, "user"
    cfg = normalize(str(ctx.config.data.get("general", {}).get("language", "")))
    if cfg:
        return cfg, "system"
    return None, "unset"


def save(ctx, code: str) -> str:
    """Persist the choice: system-wide for root, otherwise a personal preference. Returns where."""
    code = normalize(code) or ""
    if code not in LANGS:
        raise ValueError(code)
    if ctx.is_root:
        ctx.config.set("general", "language", code)
        ctx.config.save()
        return "system"
    homes = ctx.user_homes()
    write_user_pref(homes[0], code)
    return "user"
