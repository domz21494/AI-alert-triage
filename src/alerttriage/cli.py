"""Command-line entry point.

    alerttriage parse    FILE [--year Y]                    normalized JSON events + parse stats
    alerttriage simulate --seed N --out data/sim/test       labeled synthetic auth.log
    alerttriage detect   FILE [--year Y]                    alerts as JSON lines
    alerttriage eval     LOG LABELS [--out results/x]       metrics vs ground truth
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

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


def cmd_simulate(args: argparse.Namespace) -> int:
    from alerttriage.sim import write_dataset

    log, labels = write_dataset(Path(args.out), args.seed, args.hours, args.attacks_per_type)
    rows = [json.loads(x) for x in labels.read_text().splitlines()]
    mal = sum(r["malicious"] for r in rows)
    incs = len({r["incident"] for r in rows if r["incident"]})
    print(f"wrote {log} ({len(rows):,} lines, {mal:,} malicious, {incs} attack incidents) "
          f"and {labels}", file=sys.stderr)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    from alerttriage.detect.engine import DetectionEngine

    events = []
    with open(args.path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if (ev := parse_line(line, args.year)) is not None:
                ev.line_no = i
                events.append(ev)
    alerts = DetectionEngine().run(events)
    for a in alerts:
        sys.stdout.write(a.model_dump_json() + "\n")
    print(f"events={len(events)} alerts={len(alerts)}", file=sys.stderr)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from alerttriage.evaluate import evaluate, to_markdown

    r = evaluate(Path(args.log), Path(args.labels), args.year)
    md = to_markdown(r, args.title)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.with_suffix(".json").write_text(json.dumps(r, indent=2, default=str))
        out.with_suffix(".md").write_text(md)
        print(f"wrote {out.with_suffix('.md')} and {out.with_suffix('.json')}", file=sys.stderr)
    print(md)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="alerttriage")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("parse", help="Parse an auth.log file into normalized JSON events")
    sp.add_argument("path")
    sp.add_argument("--year", type=int, default=None)
    sp.add_argument("--quiet", action="store_true", help="Only print stats")
    sp.set_defaults(func=cmd_parse)

    sp = sub.add_parser("simulate", help="Generate a labeled synthetic auth.log")
    sp.add_argument("--seed", type=int, required=True)
    sp.add_argument("--out", required=True, help="Output path prefix, e.g. data/sim/test")
    sp.add_argument("--hours", type=int, default=24)
    sp.add_argument("--attacks-per-type", type=int, default=2)
    sp.set_defaults(func=cmd_simulate)

    sp = sub.add_parser("detect", help="Run detection rules on a log file")
    sp.add_argument("path")
    sp.add_argument("--year", type=int, default=None)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("eval", help="Evaluate detections against labels")
    sp.add_argument("log")
    sp.add_argument("labels")
    sp.add_argument("--year", type=int, default=2026)
    sp.add_argument("--out", help="Write <out>.md and <out>.json")
    sp.add_argument("--title", default="Detection results")
    sp.set_defaults(func=cmd_eval)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into `head`
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
