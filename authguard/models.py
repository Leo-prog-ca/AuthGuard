from dataclasses import dataclass


@dataclass
class AuthEvent:
    event_type: str
    username: str
    ip: str
    port: str = ""
    method: str = ""
    raw: str = ""
    invalid_user: bool = False


@dataclass
class Alert:
    severity: str
    category: str
    ip: str
    message: str


@dataclass
class LoginRecord:
    username: str
    ip: str
    raw: str


@dataclass
class RemoteConnection:
    netid: str
    state: str
    local: str
    remote: str
    ip: str
    process: str


@dataclass
class ListeningSocket:
    netid: str
    state: str
    local_address: str
    process: str
