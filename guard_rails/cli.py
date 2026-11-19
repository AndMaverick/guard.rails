"""Command line: ``python -m guard_rails redact|check|scan``. Reads a file or stdin, never sends anything anywhere."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .detectors import find, redact
from .policy import Policy


def _read(path: str | None) -> str:
    if path and path != "-":
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guard_rails", description="Redact personal data and secrets, and check text for prompt injection.")
    ap.add_argument("--version", action="version", version=f"guard.rails {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("redact", "print the text with sensitive values replaced"),
                           ("check", "exit 0 if the policy allows the text, 1 if not"),
                           ("scan", "list findings as JSON (no values)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("file", nargs="?", help="input file, or - for stdin (default)")
    sub.choices["check"].add_argument("--max-chars", type=int, default=8000)
    sub.choices["check"].add_argument("--threshold", type=int, default=3, help="injection score that blocks")
    sub.choices["check"].add_argument("--block-pii", action="store_true", help="block on any personal data (for outputs)")
    args = ap.parse_args(argv)
    text = _read(args.file)
    if args.cmd == "redact":
        sys.stdout.write(redact(text)[0])
        return 0
    if args.cmd == "scan":
        found = [{"kind": f.kind, "category": f.category, "start": f.start, "end": f.end} for f in find(text)]
        json.dump({"findings": found}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    verdict = Policy(max_chars=args.max_chars, injection_threshold=args.threshold, block_on_pii=args.block_pii).check(text)
    json.dump(verdict.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if verdict.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
