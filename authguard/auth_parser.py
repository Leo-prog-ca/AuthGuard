from collections import Counter

from .models import AuthEvent
from .settings import (
    ACCEPTED_RE,
    AUTH_FAILURE_RE,
    FAILED_INVALID_RE,
    FAILED_RE,
    INVALID_USER_RE,
    IP_RE,
    PKEXEC_RE,
    SUDO_RE,
    SU_RE,
)


def parse_linux_auth(lines: list[str]) -> list[AuthEvent]:
    events = []

    for line in lines:
        raw = line.strip()

        failed_invalid = FAILED_INVALID_RE.search(line)
        failed = FAILED_RE.search(line)
        accepted = ACCEPTED_RE.search(line)
        invalid_user = INVALID_USER_RE.search(line)
        auth_failure = AUTH_FAILURE_RE.search(line)

        if failed_invalid:
            events.append(
                AuthEvent(
                    event_type="failed_ssh_login",
                    username=failed_invalid.group("user"),
                    ip=failed_invalid.group("ip"),
                    port=failed_invalid.group("port"),
                    method="password",
                    raw=raw,
                    invalid_user=True
                )
            )

        elif failed:
            events.append(
                AuthEvent(
                    event_type="failed_ssh_login",
                    username=failed.group("user"),
                    ip=failed.group("ip"),
                    port=failed.group("port"),
                    method="password",
                    raw=raw
                )
            )

        elif accepted:
            events.append(
                AuthEvent(
                    event_type="accepted_ssh_login",
                    username=accepted.group("user"),
                    ip=accepted.group("ip"),
                    port=accepted.group("port"),
                    method=accepted.group("method"),
                    raw=raw
                )
            )

        elif invalid_user:
            events.append(
                AuthEvent(
                    event_type="invalid_user",
                    username=invalid_user.group("user"),
                    ip=invalid_user.group("ip"),
                    raw=raw,
                    invalid_user=True
                )
            )

        elif auth_failure and SUDO_RE.search(line):
            events.append(
                AuthEvent(
                    event_type="sudo_auth_failure",
                    username="local_user",
                    ip="localhost",
                    method="sudo",
                    raw=raw
                )
            )

        elif auth_failure and SU_RE.search(line):
            events.append(
                AuthEvent(
                    event_type="su_auth_failure",
                    username="local_user",
                    ip="localhost",
                    method="su",
                    raw=raw
                )
            )

        elif auth_failure and PKEXEC_RE.search(line):
            events.append(
                AuthEvent(
                    event_type="pkexec_auth_failure",
                    username="local_user",
                    ip="localhost",
                    method="pkexec",
                    raw=raw
                )
            )

    return events


def top_log_ips(lines: list[str], limit: int) -> list[tuple[str, int]]:
    counter = Counter()

    for line in lines:
        for ip in IP_RE.findall(line):
            if ip.startswith(("127.", "0.")):
                continue
            counter[ip] += 1

    return counter.most_common(limit)
