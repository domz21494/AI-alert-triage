"""Score detections against ground-truth labels.

Two views, because they answer different questions:

* incident-level (primary): did we raise at least one alert for each attack? how many alerts
  were false alarms? how fast did we detect? -> what a SOC analyst actually experiences
* event-level (secondary): which individual log lines were flagged? -> comparable with ML later
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from alerttriage.detect.engine import DetectionEngine
from alerttriage.ingest.authlog import parse_line
from alerttriage.schema import Alert, Event


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def load(log_path: Path, labels_path: Path, year: int) -> tuple[list[Event], list[dict], int]:
    labels = [json.loads(x) for x in labels_path.read_text().splitlines()]
    events, n_lines = [], 0
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            n_lines += 1
            if (ev := parse_line(line, year)) is not None:
                ev.line_no = i
                ev.label = labels[i]["malicious"]
                events.append(ev)
    if n_lines != len(labels):
        raise ValueError(f"{n_lines} log lines but {len(labels)} labels")
    return events, labels, n_lines


def score(events: list[Event], labels: list[dict], alerts: list[Alert]) -> dict[str, Any]:
    by_line = {e.line_no: e for e in events}
    n = len(labels)

    # ---------------- event level
    flagged = {ln for a in alerts for ln in a.line_nos}
    tp = sum(1 for i in range(n) if labels[i]["malicious"] and i in flagged)
    fp = sum(1 for i in flagged if not labels[i]["malicious"])
    fn = sum(1 for i in range(n) if labels[i]["malicious"] and i not in flagged)
    event_level = {"tp": tp, "fp": fp, "fn": fn, **_prf(tp, fp, fn)}

    # ---------------- incident level
    inc_lines: dict[str, set[int]] = defaultdict(set)
    inc_scenario: dict[str, str] = {}
    for lab in labels:
        if lab["incident"]:
            inc_lines[lab["incident"]].add(lab["line"])
            inc_scenario[lab["incident"]] = lab["scenario"]

    # Strict attribution: an alert only counts for the incident(s) that own most of its lines.
    # Otherwise an unrelated attack that happens to touch the same alert gets free credit.
    line_inc = {lab["line"]: lab["incident"] for lab in labels if lab["incident"]}
    credited: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        counts: dict[str, int] = defaultdict(int)
        for ln in a.line_nos:
            if ln in line_inc:
                counts[line_inc[ln]] += 1
        if counts:
            top = max(counts.values())
            for inc, c in counts.items():
                if c == top:
                    credited[inc].append(a)

    incidents = []
    for inc, lines in sorted(inc_lines.items()):
        hits = credited.get(inc, [])
        start = min(by_line[ln].timestamp for ln in lines if ln in by_line)
        ttd = min((a.fired_at - start).total_seconds() for a in hits) if hits else None
        incidents.append({
            "incident": inc, "scenario": inc_scenario[inc], "detected": bool(hits),
            "alerts": len(hits), "rules": sorted({a.rule_id for a in hits}),
            "time_to_detect_s": ttd,
        })

    per_scenario: dict[str, dict[str, Any]] = {}
    for sc in sorted({i["scenario"] for i in incidents}):
        rows = [i for i in incidents if i["scenario"] == sc]
        det = [i for i in rows if i["detected"]]
        ttds = [i["time_to_detect_s"] for i in det]
        per_scenario[sc] = {
            "incidents": len(rows), "detected": len(det),
            "recall": round(len(det) / len(rows), 4),
            "median_ttd_s": sorted(ttds)[len(ttds) // 2] if ttds else None,
        }

    # an alert is a true positive if it covers at least one malicious line
    def alert_tp(a: Alert) -> bool:
        return any(labels[ln]["malicious"] for ln in a.line_nos)

    per_rule: dict[str, dict[str, Any]] = {}
    for a in alerts:
        r = per_rule.setdefault(a.rule_id, {"title": a.title, "alerts": 0, "true_positive": 0})
        r["alerts"] += 1
        r["true_positive"] += alert_tp(a)
    for r in per_rule.values():
        r["precision"] = round(r["true_positive"] / r["alerts"], 4)

    n_tp_alerts = sum(alert_tp(a) for a in alerts)
    detected = sum(i["detected"] for i in incidents)
    all_ttd = sorted(i["time_to_detect_s"] for i in incidents if i["detected"])
    incident_level = {
        "incidents": len(incidents),
        "detected": detected,
        "recall": round(detected / len(incidents), 4) if incidents else 0.0,
        "alerts": len(alerts),
        "true_positive_alerts": n_tp_alerts,
        "false_positive_alerts": len(alerts) - n_tp_alerts,
        "alert_precision": round(n_tp_alerts / len(alerts), 4) if alerts else 0.0,
        "median_time_to_detect_s": all_ttd[len(all_ttd) // 2] if all_ttd else None,
    }

    return {
        "log_lines": n,
        "malicious_lines": sum(lab["malicious"] for lab in labels),
        "alert_reduction": round(1 - len(alerts) / n, 4) if n else 0.0,
        "incident_level": incident_level,
        "event_level": event_level,
        "per_scenario": per_scenario,
        "per_rule": dict(sorted(per_rule.items())),
        "incidents": incidents,
        "false_positives": [
            {"alert": a.id, "rule": a.rule_id, "title": a.title,
             "sample": a.sample[0] if a.sample else ""}
            for a in alerts if not alert_tp(a)
        ],
    }


def evaluate(log_path: Path, labels_path: Path, year: int = 2026,
             engine: DetectionEngine | None = None) -> dict[str, Any]:
    events, labels, _ = load(log_path, labels_path, year)
    engine = engine or DetectionEngine()
    t0 = time.perf_counter()
    alerts = engine.run(events)
    elapsed = time.perf_counter() - t0
    result = score(events, labels, alerts)
    result["detection_time_s"] = round(elapsed, 4)
    result["throughput_events_per_s"] = round(len(events) / elapsed) if elapsed else None
    result["rules_loaded"] = len(engine.rules)
    return result


def to_markdown(r: dict[str, Any], title: str) -> str:
    il, el = r["incident_level"], r["event_level"]
    out = [f"# {title}", "",
           f"Log lines: **{r['log_lines']:,}** ({r['malicious_lines']:,} malicious) · "
           f"rules: {r['rules_loaded']} · detection throughput: "
           f"{r['throughput_events_per_s']:,} events/s", "",
           "## Summary", "", "| Metric | Value |", "|---|---|",
           f"| Attack incidents detected (recall) | {il['detected']}/{il['incidents']} "
           f"({il['recall']:.0%}) |",
           f"| Alerts raised | {il['alerts']} |",
           f"| Alert precision (alerts that were real attacks) | {il['alert_precision']:.0%} |",
           f"| False-positive alerts | {il['false_positive_alerts']} |",
           f"| Alert reduction (log lines → alerts) | {r['alert_reduction']:.2%} |",
           f"| Median time to detect | {il['median_time_to_detect_s']} s |",
           f"| Event-level precision / recall / F1 | {el['precision']:.2f} / {el['recall']:.2f} "
           f"/ {el['f1']:.2f} |", "",
           "## Detection by attack type", "",
           "| Scenario | Detected | Recall | Median time to detect |", "|---|---|---|---|"]
    for sc, v in r["per_scenario"].items():
        ttd = f"{v['median_ttd_s']:.0f} s" if v["median_ttd_s"] is not None else "–"
        out.append(f"| {sc} | {v['detected']}/{v['incidents']} | {v['recall']:.0%} | {ttd} |")
    out += ["", "## Per rule", "", "| Rule | Title | Alerts | True positive | Precision |",
            "|---|---|---|---|---|"]
    for rid, v in r["per_rule"].items():
        out.append(f"| {rid} | {v['title']} | {v['alerts']} | {v['true_positive']} | "
                   f"{v['precision']:.0%} |")
    if r["false_positives"]:
        out += ["", "## False positives", "", "| Rule | Example log line |", "|---|---|"]
        for fp in r["false_positives"][:15]:
            out.append(f"| {fp['rule']} | `{fp['sample']}` |")
    return "\n".join(out) + "\n"
