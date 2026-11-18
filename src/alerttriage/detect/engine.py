"""Rule-based detection engine.

Rules are YAML files (one rule per file, Sigma-inspired) in `detect/rules/`. Three rule types:

* single    – every matching event raises an alert
* threshold – N matching events (or N distinct values of a field) for the same group
              (e.g. src_ip) inside a sliding time window
* sequence  – step 1 seen at least `min_count` times, then step 2, same group, inside a window

Field conditions in `match`:
    field: value                    equality
    field: [a, b]                   any of
    field: {regex: "..."}           regex search
    field: {exists: true}           not null / not empty
    field: {not_in: [a, b]}         none of
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from alerttriage.schema import Alert, Event, Severity

RULES_DIR = Path(__file__).parent / "rules"


# --------------------------------------------------------------------------- matching
def _check(actual: Any, cond: Any) -> bool:
    if isinstance(cond, dict):
        for op, val in cond.items():
            if op == "regex":
                if actual is None or not re.search(val, str(actual)):
                    return False
            elif op == "exists":
                if (actual not in (None, "")) != bool(val):
                    return False
            elif op == "not_in":
                if actual in val:
                    return False
            else:
                raise ValueError(f"unknown operator: {op}")
        return True
    if isinstance(cond, list):
        return actual in cond
    return actual == cond


def matches(event: Event, conditions: dict[str, Any]) -> bool:
    return all(_check(getattr(event, f, None), c) for f, c in conditions.items())


# --------------------------------------------------------------------------- rules
@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    mitre: dict[str, str]
    type: str = "single"
    description: str = ""
    match: dict[str, Any] = field(default_factory=dict)
    group_by: str | None = None
    threshold: int = 1
    distinct: str | None = None
    window_seconds: int = 0
    steps: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Rule:
        rule = cls(**{**d, "severity": Severity(d["severity"])})
        if rule.type not in {"single", "threshold", "sequence"}:
            raise ValueError(f"{rule.id}: unknown rule type {rule.type!r}")
        if rule.type == "sequence" and len(rule.steps) != 2:
            raise ValueError(f"{rule.id}: sequence rules need exactly 2 steps")
        if rule.type in {"threshold", "sequence"} and not (rule.group_by and rule.window_seconds):
            raise ValueError(f"{rule.id}: {rule.type} rules need group_by and window_seconds")
        return rule


def load_rules(path: Path = RULES_DIR) -> list[Rule]:
    rules = [Rule.from_dict(yaml.safe_load(p.read_text())) for p in sorted(path.glob("*.yml"))]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


# --------------------------------------------------------------------------- engine
@dataclass
class _Open:
    """An alert that is still absorbing events (same burst)."""

    alert: Alert
    last_ts: Any


class DetectionEngine:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else load_rules()

    def run(self, events: Iterable[Event]) -> list[Alert]:
        ordered = sorted(events, key=lambda e: e.timestamp)  # stable sort
        alerts: list[Alert] = []
        windows: dict[tuple, deque[Event]] = {}
        open_alerts: dict[tuple, _Open] = {}

        def new_alert(rule: Rule, evs: list[Event], group_val: str | None) -> Alert:
            a = Alert(
                id=f"{rule.id}-{len(alerts) + 1:05d}",
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                mitre_technique=rule.mitre["technique"],
                mitre_name=rule.mitre["name"],
                mitre_tactic=rule.mitre["tactic"],
                host=evs[-1].host,
                group_by=rule.group_by,
                group_value=group_val,
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                fired_at=evs[-1].timestamp,
                event_count=len(evs),
                line_nos=[e.line_no for e in evs if e.line_no is not None],
                sample=[e.raw for e in evs[:5]],
            )
            alerts.append(a)
            return a

        def extend(o: _Open, ev: Event) -> None:
            o.alert.last_seen = ev.timestamp
            o.alert.event_count += 1
            if ev.line_no is not None:
                o.alert.line_nos.append(ev.line_no)
            if len(o.alert.sample) < 5:
                o.alert.sample.append(ev.raw)
            o.last_ts = ev.timestamp

        for ev in ordered:
            for rule in self.rules:
                if rule.type == "single":
                    if matches(ev, rule.match):
                        new_alert(rule, [ev], None)
                    continue

                gval = getattr(ev, rule.group_by)
                if gval in (None, ""):
                    continue
                key = (rule.id, ev.host, gval)
                win = rule.window_seconds

                if rule.type == "threshold":
                    if not matches(ev, rule.match):
                        continue
                    o = open_alerts.get(key)
                    if o and (ev.timestamp - o.last_ts).total_seconds() <= win:
                        extend(o, ev)  # same burst -> one alert, not hundreds
                        continue
                    open_alerts.pop(key, None)
                    dq = windows.setdefault(key, deque())
                    dq.append(ev)
                    while (ev.timestamp - dq[0].timestamp).total_seconds() > win:
                        dq.popleft()
                    count = (
                        len({getattr(e, rule.distinct) for e in dq}) if rule.distinct else len(dq)
                    )
                    if count >= rule.threshold:
                        open_alerts[key] = _Open(new_alert(rule, list(dq), str(gval)), ev.timestamp)
                        dq.clear()

                else:  # sequence
                    step1, step2 = rule.steps
                    is1, is2 = matches(ev, step1["match"]), matches(ev, step2["match"])
                    if not (is1 or is2):
                        continue
                    dq = windows.setdefault(key, deque())
                    while dq and (ev.timestamp - dq[0].timestamp).total_seconds() > win:
                        dq.popleft()
                    if is1:
                        dq.append(ev)
                    elif is2:
                        if len(dq) >= step1.get("min_count", 1):
                            new_alert(rule, [*dq, ev], str(gval))
                            dq.clear()
        return alerts
