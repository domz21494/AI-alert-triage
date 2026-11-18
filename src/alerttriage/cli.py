"""Command-line entry point.

    alerttriage parse path/to/auth.log [--year 2026]   -> JSON lines + parse stats on stderr
"""

from __future__ import annotations

import argparse
import sys
import time

from alerttriage.ingest.authlog import parse_line
from alerttriage.schema import EventType


def cmd_parse(args: argparse.Namespace) -> int:
    total = parsed = other = 0
    start = time.perf_counter()
    with open(args.path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total += 1
            ev = parse_line(line, args.year)
            if ev is None:
                continue
            parsed += 1
            if ev.event_type == EventType.OTHER:
                other += 1
            if not args.quiet:
                sys.stdout.write(ev.model_dump_json() + "\n")
    elapsed = time.perf_counter() - start
    eps = total / elapsed if elapsed else 0.0
    print(
        f"lines={total} parsed={parsed} ({parsed / max(total, 1):.1%}) "
        f"classified={parsed - other} ({(parsed - other) / max(total, 1):.1%}) "
        f"time={elapsed:.3f}s throughput={eps:,.0f} lines/s",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="alerttriage")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("parse", help="Parse an auth.log file into normalized JSON events")
    sp.add_argument("path")
    sp.add_argument("--year", type=int, default=None)
    sp.add_argument("--quiet", action="store_true", help="Only print stats")
    sp.set_defaults(func=cmd_parse)
    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into `head`
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
