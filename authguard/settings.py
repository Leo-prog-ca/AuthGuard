import re


DEFAULT_SINCE = "24 hours ago"
DEFAULT_LIMIT = 20

AUTH_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILED_INVALID_RE = re.compile(
    r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\w\.:]+) port (?P<port>\d+)"
)

FAILED_RE = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>[\w\.:]+) port (?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\w\.:]+) port (?P<port>\d+)"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\w\.:]+)"
)

AUTH_FAILURE_RE = re.compile(r"authentication failure", re.IGNORECASE)
SUDO_RE = re.compile(r"sudo", re.IGNORECASE)
SU_RE = re.compile(r"\bsu\b|su:", re.IGNORECASE)
PKEXEC_RE = re.compile(r"pkexec", re.IGNORECASE)
