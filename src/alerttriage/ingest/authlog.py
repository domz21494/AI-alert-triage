"""Parser for Linux auth.log / secure / syslog (sshd, PAM, sudo, su, useradd, ftpd).

Example line:
    Nov 18 10:15:32 web01 sshd[1234]: Failed password for invalid user admin
        from 203.0.113.5 port 52314 ssh2   (one line in the real log)

Patterns are table-driven: (event_type, process filter, regex). First match wins,
so specific patterns come before general ones. Named groups user/ip/port/cmd are
copied onto the Event.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from alerttriage.schema import Event, EventType

# Syslog header: "Mon DD HH:MM:SS host process(sub)[pid]: message"
HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\((?P<sub>[\w\-]+)\))?(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)"
ANY = None  # matches any process

PATTERNS: list[tuple[EventType, set[str] | None, re.Pattern[str]]] = [
    # --- sshd ---
    (EventType.SSH_LOGIN_FAILED, {"sshd"}, re.compile(
        rf"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
        rf"from {IP} port (?P<port>\d+)")),
    (EventType.SSH_LOGIN_SUCCESS, {"sshd"}, re.compile(
        rf"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
        rf"from {IP} port (?P<port>\d+)")),
    (EventType.SSH_INVALID_USER, {"sshd"}, re.compile(
        rf"Invalid user (?P<user>\S*) from {IP}(?: port (?P<port>\d+))?")),
    (EventType.SSH_INVALID_USER, {"sshd"}, re.compile(
        r"input_userauth_request: invalid user (?P<user>\S+)")),
    (EventType.SSH_BREAKIN_ATTEMPT, {"sshd"}, re.compile(
        rf"reverse mapping checking .*\[{IP}\] failed - POSSIBLE BREAK-IN ATTEMPT")),
    (EventType.SSH_SCAN, {"sshd"}, re.compile(
        rf"Did not receive identification string from {IP}")),
    (EventType.SSH_MAX_AUTH, {"sshd"}, re.compile(
        r"(?:PAM \d+ more authentication failures|maximum authentication attempts exceeded"
        r"|ignoring max retries)")),
    (EventType.SSH_DISCONNECT, {"sshd"}, re.compile(
        r"(?:Received disconnect from|Disconnected from|Connection closed by)"
        rf"(?: (?:invalid |authenticating )?user (?P<user>\S+))? {IP}(?: port (?P<port>\d+))?")),
    # --- PAM (any service) ---
    (EventType.AUTH_FAILURE, ANY, re.compile(
        r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")),
    (EventType.AUTH_FAILURE, {"klogind"}, re.compile(r"authentication failed")),
    (EventType.USER_UNKNOWN, ANY, re.compile(r"check pass; user unknown")),
    # --- privilege ---
    (EventType.SUDO_COMMAND, {"sudo"}, re.compile(
        r"^\s*(?P<user>\S+) : .*?USER=\S+ ; COMMAND=(?P<cmd>.+)$")),
    (EventType.SUDO_AUTH_FAILURE, {"sudo"}, re.compile(
        r"(?P<user>\S+) : \d+ incorrect password attempts")),
    (EventType.SU_SESSION, {"su"}, re.compile(
        r"session opened for user (?P<target>\S+) by (?P<user>[^\s(]*)")),
    (EventType.SESSION_OPENED, ANY, re.compile(r"session opened for user (?P<user>\S+)")),
    (EventType.SESSION_CLOSED, ANY, re.compile(r"session closed for user (?P<user>\S+)")),
    (EventType.USER_ADDED, {"useradd", "adduser"}, re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    # --- other network services ---
    (EventType.FTP_CONNECTION, {"ftpd", "vsftpd", "proftpd"}, re.compile(
        rf"connection from {IP}")),
]


def _parse_ts(ts: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int | None = None) -> Event | None:
    """Parse one syslog line. Returns None if the line is not a syslog line."""
    line = line.rstrip("\n")
    m = HEADER.match(line)
    if not m:
        return None

    proc = m["proc"]
    msg = m["msg"]
    base = dict(
        timestamp=_parse_ts(m["ts"], year or datetime.now().year),
        host=m["host"],
        source="auth",
        process=proc,
        pid=int(m["pid"]) if m["pid"] else None,
        raw=line,
    )

    for etype, procs, pat in PATTERNS:
        if procs is not None and proc not in procs:
            continue
        if sm := pat.search(msg):
            g = sm.groupdict()
            # sudo auth failure arrives via PAM: user= is the invoking user, not remote
            if proc == "sudo" and etype == EventType.AUTH_FAILURE:
                etype = EventType.SUDO_AUTH_FAILURE
            return Event(
                **base,
                event_type=etype,
                user=g.get("user") or None,
                src_ip=g.get("ip") or None,
                src_port=int(g["port"]) if g.get("port") else None,
                command=g["cmd"].strip() if g.get("cmd") else None,
            )

    return Event(**base, event_type=EventType.OTHER)


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    for line in lines:
        if (ev := parse_line(line, year)) is not None:
            yield ev
