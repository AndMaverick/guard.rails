"""Redact a stream of text chunks without letting a secret slip through a chunk boundary.

A model streams tokens, and "4111 1111" arrives before "1111 1111". Redacting each chunk alone would miss the
card. ``StreamRedactor`` keeps a tail of recent text unreleased, releases only what cannot be part of a later
match, and redacts what it releases. ``hold`` must exceed the longest value you need to catch (a card or an API
key is well under 100 characters; a private key block is longer, and an unterminated block is held back whole).
"""
from __future__ import annotations

from .detectors import find, redact

_BEGIN = "-----BEGIN "


class StreamRedactor:
    def __init__(self, hold: int = 128, only: list[str] | None = None) -> None:
        if hold < 1:
            raise ValueError("hold must be at least 1")
        self.hold, self._only = hold, only
        self._buffer = ""

    def _safe_cut(self) -> int:
        cut = max(0, len(self._buffer) - self.hold)
        # never release in the middle of a complete match: move the cut back to its start
        for f in find(self._buffer, only=self._only):
            if f.start < cut < f.end:
                cut = f.start
                break
        # an unterminated private key block is held back until it closes
        begin = self._buffer.rfind(_BEGIN)
        if begin >= 0 and "-----END " not in self._buffer[begin:]:
            cut = min(cut, begin)
        return cut

    def feed(self, chunk: str) -> str:
        """Add a chunk and return the text that is now safe to release, already redacted."""
        self._buffer += chunk
        cut = self._safe_cut()
        released, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return redact(released, only=self._only)[0] if released else ""

    def flush(self) -> str:
        """The end of the stream: release and redact whatever is left."""
        rest, self._buffer = self._buffer, ""
        return redact(rest, only=self._only)[0] if rest else ""
