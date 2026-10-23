"""CLI: triage one or many files, or a directory.

    quarry scan suspicious.jpg
    quarry scan ./downloads --min-severity medium --json
    quarry entropy payload.bin
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .containers import analyse, shannon

ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
MARK = {"high": "!!", "medium": "! ", "low": "· ", "info": "  "}


def iter_files(target: str):
    p = Path(target)
    if p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file():
                yield f
    elif p.is_file():
        yield p
    else:
        raise SystemExit(f"not found: {target}")


def cmd_scan(args) -> int:
    floor = ORDER[args.min_severity]
    total = 0
    flagged = 0
    results = []

    for f in iter_files(args.path):
        try:
            data = f.read_bytes()
        except OSError as exc:
            print(f"{f}: unreadable ({exc})", file=sys.stderr)
            continue
        report = analyse(data)
        total += 1
        hits = [x for x in report.findings if ORDER[x.severity] >= floor]
        if any(x.severity in ("high", "medium") for x in report.findings):
            flagged += 1

        if args.json:
            results.append({"path": str(f), **report.as_dict()})
            continue

        print(f"\n{f}  [{report.format}, {report.size} bytes]")
        if not hits:
            print("  clean at this severity")
        for x in sorted(hits, key=lambda z: -ORDER[z.severity]):
            print(f"  {MARK[x.severity]}{x.severity:<6} {x.kind}: {x.detail}")

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{total} file(s), {flagged} with medium or high findings")
    return 1 if (args.fail_on and flagged) else 0


def cmd_entropy(args) -> int:
    data = Path(args.path).read_bytes()
    print(f"{args.path}: {len(data)} bytes, entropy {shannon(data):.3f} bits/byte")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quarry", description="Structural file triage.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="triage a file or directory")
    s.add_argument("path")
    s.add_argument("--min-severity", choices=list(ORDER), default="low")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", action="store_true", help="exit 1 if anything medium+ was found")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("entropy", help="report the entropy of a file")
    e.add_argument("path")
    e.set_defaults(func=cmd_entropy)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
