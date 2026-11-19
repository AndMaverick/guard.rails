"""Policy: one object that turns the detectors and the injection score into a verdict with every reason."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .detectors import Finding, redact
from .injection import explain, injection_score, normalise


@dataclass
class Verdict:
    allowed: bool
    reasons: list[str]
    clean_text: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    matched: list[str] = field(default_factory=list)  # injection rule labels, for logs and tuning

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed, "reasons": self.reasons, "score": self.score, "matched": self.matched,
            "findings": [{"kind": f.kind, "category": f.category, "start": f.start, "end": f.end} for f in self.findings],
        }  # values are deliberately left out: a log of what was redacted must not contain it


@dataclass
class Policy:
    """Rules for one direction of traffic.

    * ``block_on_pii``: for outputs, where leaking personal data is the failure.
    * ``block_secrets``: refuse text that contains a credential (private key, cloud token, API key). On by default,
      because a key in a prompt or a reply is never intended.
    * ``block_kinds``: refuse specific finding kinds, e.g. ``("CARD", "IBAN")``.
    * ``redact_kinds``: limit redaction to these kinds (default: all).
    """

    max_chars: int = 8000
    injection_threshold: int = 3
    blocked_terms: tuple[str, ...] = ()
    redact_pii: bool = True
    block_on_pii: bool = False
    block_secrets: bool = True
    block_kinds: tuple[str, ...] = ()
    redact_kinds: tuple[str, ...] | None = None

    def check(self, text: str) -> Verdict:
        reasons: list[str] = []
        if len(text) > self.max_chars:
            reasons.append(f"length {len(text)} exceeds {self.max_chars}")
        hits = explain(text)
        score = sum(w for _label, w in hits)
        if score >= self.injection_threshold:
            reasons.append(f"injection score {score}")
        lowered = normalise(text).casefold()
        reasons += [f"blocked term: {t}" for t in self.blocked_terms if normalise(t).casefold() in lowered]
        only = list(self.redact_kinds) if self.redact_kinds is not None else None
        clean, findings = redact(text, only=only)
        if self.block_on_pii and findings:
            reasons.append("personal data: " + ", ".join(sorted({f.kind for f in findings})))
        elif self.block_kinds:
            hit = sorted({f.kind for f in findings if f.kind in self.block_kinds})
            if hit:
                reasons.append("blocked data: " + ", ".join(hit))
        if self.block_secrets:
            secrets = sorted({f.kind for f in findings if f.category == "secret"})
            if secrets:
                reasons.append("secret: " + ", ".join(secrets))
        return Verdict(not reasons, reasons, clean if self.redact_pii else text, findings, score, [lbl for lbl, _w in hits])


ContentPolicy = Policy  # the name used by mao-framework


def guard_verifier(policy: Policy) -> Callable[[Any], bool]:
    """A ``Step.verify`` check for mao-framework. Output that fails the policy never reaches a dependent step."""

    def verify(output: Any) -> bool:
        return policy.check(output if isinstance(output, str) else str(output)).allowed

    return verify


__all__ = ["Policy", "ContentPolicy", "Verdict", "guard_verifier", "injection_score"]
