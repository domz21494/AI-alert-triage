"""Common event schema: every log source is normalized into an Event."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class EventType(StrEnum):
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_DISCONNECT = "ssh_disconnect"
    SSH_BREAKIN_ATTEMPT = "ssh_breakin_attempt"
    SSH_SCAN = "ssh_scan"
    SSH_MAX_AUTH = "ssh_max_auth"
    AUTH_FAILURE = "auth_failure"
    USER_UNKNOWN = "user_unknown"
    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAILURE = "sudo_auth_failure"
    SU_SESSION = "su_session"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    USER_ADDED = "user_added"
    FTP_CONNECTION = "ftp_connection"
    OTHER = "other"


class Event(BaseModel):
    """A single normalized log event."""

    timestamp: datetime
    host: str
    source: str = Field(description="Log source, e.g. 'auth'")
    process: str
    pid: int | None = None
    event_type: EventType
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    command: str | None = None
    raw: str
    # Position of the line in its source file (0-based); used to join with label files.
    line_no: int | None = None
    # Ground-truth label (True = malicious). Only set for labeled datasets / attack lab.
    label: bool | None = None


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    """Raised by the detection engine when a rule matches one or more events."""

    id: str
    rule_id: str
    title: str
    severity: Severity
    mitre_technique: str
    mitre_name: str
    mitre_tactic: str
    host: str
    group_by: str | None = None
    group_value: str | None = None
    first_seen: datetime
    last_seen: datetime
    fired_at: datetime = Field(description="Timestamp of the event that triggered the alert")
    event_count: int
    line_nos: list[int] = Field(default_factory=list)
    sample: list[str] = Field(default_factory=list, description="Up to 5 raw log lines")
