"""Reversible redaction: swap sensitive values for stable tokens, send the safe text to a model, restore the answer.

The same value always gets the same token inside one ``Pseudonymizer``, so a model can still reason about "the
same card appears twice". The mapping lives only in this object. Keep it in memory, scope it to one request, and
never log it: it is exactly the sensitive data you removed.
"""
from __future__ import annotations

import re

from .detectors import Finding, find

_TOKEN = re.compile(r"\[([A-Z_]+)_(\d+)\]")


class Pseudonymizer:
    def __init__(self, only: list[str] | None = None) -> None:
        self._only = only
        self._forward: dict[tuple[str, str], str] = {}
        self._back: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def _token(self, f: Finding) -> str:
        key = (f.kind, f.value)
        if key not in self._forward:
            n = self._counts.get(f.kind, 0) + 1
            self._counts[f.kind] = n
            token = f"[{f.kind}_{n}]"
            self._forward[key] = token
            self._back[token] = f.value
        return self._forward[key]

    def pseudonymize(self, text: str) -> str:
        out: list[str] = []
        cursor = 0
        for f in find(text, only=self._only):
            out.append(text[cursor:f.start])
            out.append(self._token(f))
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out)

    def restore(self, text: str) -> str:
        """Put original values back for tokens this object issued. Unknown tokens are left as written."""
        return _TOKEN.sub(lambda m: self._back.get(m.group(0), m.group(0)), text)

    def __len__(self) -> int:
        return len(self._back)

    def __repr__(self) -> str:  # never print the mapped values
        return f"Pseudonymizer(tokens={len(self._back)})"
