from datetime import datetime

from alerttriage.evaluate import evaluate, score
from alerttriage.ingest.authlog import parse_line
from alerttriage.schema import Alert, Severity
from alerttriage.sim import Simulator, write_dataset


def test_simulator_is_deterministic():
    a = [ln.text for ln in Simulator(7, datetime(2026, 11, 16), 6, 1).run()]
    b = [ln.text for ln in Simulator(7, datetime(2026, 11, 16), 6, 1).run()]
    assert a == b


def test_every_simulated_line_parses():
    lines = Simulator(3, datetime(2026, 11, 16), 24, 1).run()
    events = [parse_line(ln.text, 2026) for ln in lines]
    assert all(e is not None for e in events)
    classified = sum(e.event_type != "other" for e in events)
    assert classified / len(events) >= 0.95


def test_end_to_end_smoke(tmp_path):
    log, labels = write_dataset(tmp_path / "smoke", seed=3, hours=24, attacks_per_type=1)
    r = evaluate(log, labels)
    assert r["incident_level"]["incidents"] == 7
    assert r["incident_level"]["recall"] >= 0.8
    assert r["per_scenario"]["low_and_slow"]["detected"] == 0  # known blind spot of rules
    assert r["alert_reduction"] > 0.95


def _alert(lines, rule="AT-001"):
    t = datetime(2026, 11, 16)
    return Alert(id="x", rule_id=rule, title="t", severity=Severity.HIGH, mitre_technique="T1110",
                 mitre_name="n", mitre_tactic="c", host="h", first_seen=t, last_seen=t,
                 fired_at=t, event_count=len(lines), line_nos=lines)


def test_attribution_does_not_give_free_credit():
    from alerttriage.schema import Event, EventType

    t = datetime(2026, 11, 16)
    labels = ([{"line": i, "malicious": True, "scenario": "botnet", "incident": "INC-1"}
               for i in range(9)]
              + [{"line": 9, "malicious": True, "scenario": "slow", "incident": "INC-2"}]
              + [{"line": 10, "malicious": False, "scenario": "benign", "incident": None}])
    events = [Event(timestamp=t, host="h", source="auth", process="sshd",
                    event_type=EventType.SSH_LOGIN_FAILED, raw="", line_no=i) for i in range(11)]
    # one alert mostly INC-1, touching a single INC-2 line; one false-positive alert
    r = score(events, labels, [_alert(list(range(10))), _alert([10], "AT-005")])
    det = {i["incident"]: i["detected"] for i in r["incidents"]}
    assert det == {"INC-1": True, "INC-2": False}
    assert r["incident_level"]["false_positive_alerts"] == 1
    assert r["incident_level"]["alert_precision"] == 0.5
