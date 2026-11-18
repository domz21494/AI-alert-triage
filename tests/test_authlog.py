from pathlib import Path

import pytest

from alerttriage.ingest.authlog import parse_line, parse_lines
from alerttriage.schema import EventType

FIXTURE = Path(__file__).parent / "fixtures" / "auth_sample.log"


def test_failed_password_invalid_user():
    ev = parse_line(
        "Nov 18 10:15:32 web01 sshd[1234]: Failed password for invalid user admin "
        "from 203.0.113.5 port 52314 ssh2",
        year=2026,
    )
    assert ev.event_type == EventType.SSH_LOGIN_FAILED
    assert (ev.user, ev.src_ip, ev.src_port, ev.pid) == ("admin", "203.0.113.5", 52314, 1234)
    assert ev.timestamp.year == 2026


def test_accepted_publickey():
    ev = parse_line(
        "Nov 18 10:15:40 web01 sshd[1240]: Accepted publickey for alice "
        "from 198.51.100.7 port 51000 ssh2",
        year=2026,
    )
    assert ev.event_type == EventType.SSH_LOGIN_SUCCESS
    assert ev.user == "alice"


def test_sudo_command():
    ev = parse_line(
        "Nov 18 10:16:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/apt update",
        year=2026,
    )
    assert ev.event_type == EventType.SUDO_COMMAND
    assert ev.user == "alice"
    assert ev.command == "/usr/bin/apt update"


def test_non_syslog_line_returns_none():
    assert parse_line("this is not a syslog line") is None


def test_fixture_file_types():
    events = list(parse_lines(FIXTURE.read_text().splitlines(), year=2026))
    assert len(events) == 9  # last line is not syslog
    types = [e.event_type for e in events]
    assert types == [
        EventType.SSH_LOGIN_FAILED,
        EventType.SSH_LOGIN_FAILED,
        EventType.SSH_INVALID_USER,
        EventType.SSH_LOGIN_SUCCESS,
        EventType.SUDO_COMMAND,
        EventType.SUDO_AUTH_FAILURE,
        EventType.USER_ADDED,
        EventType.SSH_DISCONNECT,
        EventType.SESSION_OPENED,
    ]
    assert events[5].user == "bob"
    assert events[6].user == "backdoor"


# Real-world formats taken from Loghub (Linux / OpenSSH datasets)


@pytest.mark.parametrize(
    "line,etype,user,ip",
    [
        ("Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 "
         "euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 ",
         EventType.AUTH_FAILURE, None, "218.188.2.4"),
        ("Dec 10 06:55:48 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; "
         "logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186  user=root",
         EventType.AUTH_FAILURE, "root", "173.234.31.186"),
        ("Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for "
         "ns.example.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!",
         EventType.SSH_BREAKIN_ATTEMPT, None, "173.234.31.186"),
        ("Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
         EventType.SSH_INVALID_USER, "webmaster", "173.234.31.186"),
        ("Dec 10 07:02:47 LabSZ sshd[24203]: Received disconnect from 52.80.34.196: 11: "
         "Bye Bye [preauth]", EventType.SSH_DISCONNECT, None, "52.80.34.196"),
        ("Dec 10 09:11:20 LabSZ sshd[24434]: Did not receive identification string from "
         "103.99.0.122", EventType.SSH_SCAN, None, "103.99.0.122"),
        ("Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)",
         EventType.SU_SESSION, None, None),
        ("Jun 17 07:07:00 combo ftpd[29504]: connection from 24.54.76.216 "
         "(24-54-76-216.bflony.adelphia.net) at Fri Jun 17 07:07:00 2005 ",
         EventType.FTP_CONNECTION, None, "24.54.76.216"),
    ],
)
def test_real_world_formats(line, etype, user, ip):
    ev = parse_line(line, year=2026)
    assert ev.event_type == etype
    assert ev.user == user
    assert ev.src_ip == ip
