"""guard.rails: defensive checks for LLM input and output, with no dependencies.

Personal data and secrets (checksum-validated, including Gulf, Indonesian, UK and US identifiers), multilingual
prompt-injection scoring, reversible pseudonymisation, chunk-safe stream redaction, and a policy that returns a
verdict with every reason. Heuristics, not a security boundary: see the README for the limits.
"""
from __future__ import annotations

from .detectors import DETECTORS, Detector, Finding, find, kinds, redact
from .injection import explain, injection_score, normalise
from .policy import ContentPolicy, Policy, Verdict, guard_verifier
from .pseudonym import Pseudonymizer
from .stream import StreamRedactor
from .validators import luhn_valid

__version__ = "0.2.0"

__all__ = [
    "DETECTORS", "Detector", "Finding", "find", "kinds", "redact",
    "explain", "injection_score", "normalise",
    "ContentPolicy", "Policy", "Verdict", "guard_verifier",
    "Pseudonymizer", "StreamRedactor", "luhn_valid", "__version__",
]
