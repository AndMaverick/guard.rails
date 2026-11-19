"""Detectors for personal data and secrets, each with the validator that keeps false positives down."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from re import Pattern

from . import validators as v

_ARABIC_INDIC = {ord(c): str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")}
_PERSIAN = {ord(c): str(i) for i, c in enumerate("۰۱۲۳۴۵۶۷۸۹")}
DIGIT_MAP = {**_ARABIC_INDIC, **_PERSIAN}


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int = 0
    end: int = 0
    category: str = "pii"


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: Pattern[str]
    validate: Callable[[str], bool] | None = None
    category: str = "pii"  # "pii" or "secret"
    priority: int = 0  # higher wins when two detectors claim the same span
    standalone: bool = False  # reject a match that is a slice of a longer digit run


def _re(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


DETECTORS: list[Detector] = [
    # secrets first: they are the most damaging to leak and the most specific to recognise
    Detector("PRIVATE_KEY", _re(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), None, "secret", 100),
    Detector("JWT", _re(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), None, "secret", 90),
    Detector("AWS_KEY", _re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None, "secret", 90),
    Detector("GITHUB_TOKEN", _re(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None, "secret", 90),
    Detector("SLACK_TOKEN", _re(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), None, "secret", 90),
    Detector("STRIPE_KEY", _re(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), None, "secret", 90),
    Detector("GOOGLE_KEY", _re(r"\bAIza[0-9A-Za-z_-]{35}\b"), None, "secret", 90),
    Detector("ANTHROPIC_KEY", _re(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), None, "secret", 95),
    Detector("API_KEY", _re(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"), None, "secret", 80),
    # personal data
    Detector("EMAIL", _re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None, "pii", 50),
    Detector("IBAN", _re(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"), v.iban_valid, "pii", 60),
    Detector("EMIRATES_ID", _re(r"(?<!\d)784[- ]?\d{4}[- ]?\d{7}[- ]?\d(?!\d)"), v.emirates_id_valid, "pii", 60, True),
    Detector("NIK", _re(r"(?<!\d)\d{16}(?!\d)"), v.nik_valid, "pii", 55, True),
    Detector("CARD", _re(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), v.luhn_valid, "pii", 50),
    Detector("SSN", _re(r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)"), v.ssn_valid, "pii", 45, True),
    Detector("SAUDI_ID", _re(r"(?<!\d)[12]\d{9}(?!\d)"), v.saudi_id_valid, "pii", 40, True),
    Detector("NINO", _re(r"\b[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), v.nino_valid, "pii", 45),
    Detector("IP", _re(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)"), None, "pii", 30),
    Detector("PHONE", _re(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}(?!\d)"),
             lambda s: 9 <= sum(c.isdigit() for c in s) <= 15, "pii", 10, True),
]

_KINDS = {d.kind for d in DETECTORS}
_DIGIT_AFTER = re.compile(r"[ .-]?\d")
_DIGIT_BEFORE = re.compile(r"\d[ .-]?$")


def kinds() -> list[str]:
    return sorted(_KINDS)


def find(text: str, detectors: list[Detector] | None = None, only: list[str] | None = None) -> list[Finding]:
    """Every finding in the text, by position. Overlaps resolve to the higher priority, then the longer span.

    Matching runs on a copy with Arabic-Indic and Persian digits folded to ASCII (same length), and positions refer
    to the original text, so a message in any script is reported and replaced where it actually sits.
    """
    view = text.translate(DIGIT_MAP)
    candidates: list[tuple[int, int, int, Detector]] = []
    for det in detectors or DETECTORS:
        if only is not None and det.kind not in only:
            continue
        for match in det.pattern.finditer(view):
            raw = match.group(0)
            # digit patterns can swallow a trailing separator; a secret's own trailing dashes belong to it
            trimmed = raw.rstrip(" -") if det.category == "pii" else raw
            start, end = match.start(), match.start() + len(trimmed)
            raw = view[start:end]
            if det.validate is not None and not det.validate(raw):
                continue
            if det.standalone and (_DIGIT_AFTER.match(view, end) or _DIGIT_BEFORE.search(view[:start])):
                continue
            candidates.append((det.priority, end - start, start, det))
    candidates.sort(key=lambda c: (-c[0], -c[1], c[2]))
    taken: list[tuple[int, int]] = []
    chosen: list[Finding] = []
    for _prio, _length, start, det in candidates:
        end = start + _length
        if any(start < e and s < end for s, e in taken):
            continue
        taken.append((start, end))
        chosen.append(Finding(det.kind, text[start:end], start, end, det.category))
    return sorted(chosen, key=lambda f: f.start)


def redact(text: str, placeholder: Callable[[Finding], str] = lambda f: f"[{f.kind}]", **kw: object) -> tuple[str, list[Finding]]:
    """Replace findings with placeholders. Returns (clean_text, findings)."""
    findings = find(text, **kw)  # type: ignore[arg-type]
    out: list[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor:f.start])
        out.append(placeholder(f))
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), findings
