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
    # Ground-truth label (True = malicious). Only set for labeled datasets / attack lab.
    label: bool | None = None
