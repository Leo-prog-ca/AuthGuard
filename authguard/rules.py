from collections import defaultdict

from .models import Alert, AuthEvent


def detect_login_anomalies(
    events: list[AuthEvent],
    failed_threshold: int,
    user_threshold: int,
    sudo_threshold: int
) -> list[Alert]:
    alerts = []

    failed_by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)
    invalid_users_by_ip = defaultdict(set)

    root_failures = defaultdict(list)
    root_successes = defaultdict(list)

    sudo_failures = []
    su_failures = []
    pkexec_failures = []

    for event in events:
        if event.event_type == "failed_ssh_login":
            failed_by_ip[event.ip].append(event)

            if event.invalid_user:
                invalid_users_by_ip[event.ip].add(event.username)

            if event.username == "root":
                root_failures[event.ip].append(event)

        elif event.event_type == "invalid_user":
            invalid_users_by_ip[event.ip].add(event.username)

        elif event.event_type == "accepted_ssh_login":
            accepted_by_ip[event.ip].append(event)

            if event.username == "root":
                root_successes[event.ip].append(event)

        elif event.event_type == "sudo_auth_failure":
            sudo_failures.append(event)

        elif event.event_type == "su_auth_failure":
            su_failures.append(event)

        elif event.event_type == "pkexec_auth_failure":
            pkexec_failures.append(event)

    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= failed_threshold:
            alerts.append(
                Alert(
                    severity="HIGH",
                    category="SSH_BRUTE_FORCE",
                    ip=ip,
                    message=f"{len(attempts)} failed SSH login attempts were found from this address."
                )
            )

    for ip, usernames in invalid_users_by_ip.items():
        if len(usernames) >= user_threshold:
            alerts.append(
                Alert(
                    severity="HIGH",
                    category="USER_ENUMERATION",
                    ip=ip,
                    message=f"Multiple invalid usernames were tested: {', '.join(sorted(usernames))}."
                )
            )

    for ip, attempts in root_failures.items():
        alerts.append(
            Alert(
                severity="MEDIUM",
                category="ROOT_LOGIN_ATTEMPTS",
                ip=ip,
                message=f"{len(attempts)} failed root login attempt(s) were detected."
            )
        )

    for ip, logins in root_successes.items():
        alerts.append(
            Alert(
                severity="CRITICAL",
                category="ROOT_SUCCESSFUL_LOGIN",
                ip=ip,
                message=f"{len(logins)} successful root login record(s) were detected."
            )
        )

    for ip, logins in accepted_by_ip.items():
        failed_count = len(failed_by_ip.get(ip, []))

        if failed_count >= 3:
            users = sorted({login.username for login in logins})

            alerts.append(
                Alert(
                    severity="CRITICAL",
                    category="SUCCESS_AFTER_FAILURES",
                    ip=ip,
                    message=f"Successful login after {failed_count} failed attempt(s). User(s): {', '.join(users)}."
                )
            )

    if len(sudo_failures) >= sudo_threshold:
        alerts.append(
            Alert(
                severity="MEDIUM",
                category="SUDO_FAILURES",
                ip="localhost",
                message=f"{len(sudo_failures)} sudo authentication failure record(s) were found."
            )
        )

    if len(su_failures) >= sudo_threshold:
        alerts.append(
            Alert(
                severity="MEDIUM",
                category="SU_FAILURES",
                ip="localhost",
                message=f"{len(su_failures)} su authentication failure record(s) were found."
            )
        )

    if pkexec_failures:
        alerts.append(
            Alert(
                severity="MEDIUM",
                category="PKEXEC_FAILURES",
                ip="localhost",
                message=f"{len(pkexec_failures)} pkexec authentication failure record(s) were found."
            )
        )

    return alerts
