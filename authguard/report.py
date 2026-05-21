import csv
from datetime import datetime

from .models import Alert, AuthEvent, ListeningSocket, LoginRecord, RemoteConnection


def write_alerts_csv(alerts: list[Alert], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["severity", "category", "ip", "message"])

        for alert in alerts:
            writer.writerow([alert.severity, alert.category, alert.ip, alert.message])


def print_console_report(
    sources: list[str],
    notes: list[str],
    line_count: int,
    events: list[AuthEvent],
    alerts: list[Alert],
    top_ips: list[tuple[str, int]],
    successful_logins: list[LoginRecord],
    failed_logins: list[LoginRecord],
    connections: list[RemoteConnection],
    sockets: list[ListeningSocket],
) -> None:
    print("\nAuthGuard: Linux Security Snapshot")
    print("=" * 60)

    print("Sources:")
    if sources:
        for source in sources:
            print(f"- {source}")
    else:
        print("- no log source was readable")

    print("-" * 60)
    print(f"Log lines analyzed: {line_count}")
    print(f"Authentication events parsed: {len(events)}")
    print(f"Alerts: {len(alerts)}")
    print(f"Successful login records: {len(successful_logins)}")
    print(f"Failed login records: {len(failed_logins)}")
    print(f"Active remote connections: {len(connections)}")
    print(f"Listening sockets: {len(sockets)}")
    print("=" * 60)

    print("\nAlerts:")
    if alerts:
        for index, alert in enumerate(alerts, start=1):
            print(f"{index}. {alert.severity} / {alert.category}")
            print(f"   IP: {alert.ip}")
            print(f"   {alert.message}")
    else:
        print("- no suspicious authentication activity matched the current rules")

    print("\nTop IP addresses in logs:")
    if top_ips:
        for ip, count in top_ips:
            print(f"- {ip}: {count}")
    else:
        print("- no external IPv4 addresses found in the collected logs")

    print("\nRecent successful login IPs:")
    if successful_logins:
        for record in successful_logins[:10]:
            print(f"- {record.username} from {record.ip} | {record.raw}")
    else:
        print("- no wtmp login records were returned by last -i")

    print("\nRecent failed login IPs:")
    if failed_logins:
        for record in failed_logins[:10]:
            print(f"- {record.username} from {record.ip} | {record.raw}")
    else:
        print("- no btmp login records were returned by lastb -i")

    print("\nCurrent active remote connections:")
    if connections:
        for item in connections:
            print(f"- {item.netid} {item.state} | local {item.local} -> remote {item.remote} | {item.process}")
    else:
        print("- no active remote TCP/UDP sessions were detected")

    print("\nListening sockets:")
    if sockets:
        for item in sockets:
            print(f"- {item.netid} {item.state} | {item.local_address} | {item.process}")
    else:
        print("- no listening sockets were returned by ss")

    if notes:
        print("\nAccess notes:")
        for note in notes[:6]:
            print(f"- {note}")

    print("=" * 60)


def write_markdown_report(
    path: str,
    sources: list[str],
    line_count: int,
    events: list[AuthEvent],
    alerts: list[Alert],
    top_ips: list[tuple[str, int]],
    successful_logins: list[LoginRecord],
    failed_logins: list[LoginRecord],
    connections: list[RemoteConnection],
    sockets: list[ListeningSocket],
) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "w", encoding="utf-8") as file:
        file.write("# AuthGuard Security Report\n\n")
        file.write(f"Generated at: `{now}`\n\n")

        file.write("## Summary\n\n")
        file.write(f"- Log lines analyzed: `{line_count}`\n")
        file.write(f"- Authentication events parsed: `{len(events)}`\n")
        file.write(f"- Alerts: `{len(alerts)}`\n")
        file.write(f"- Successful login records: `{len(successful_logins)}`\n")
        file.write(f"- Failed login records: `{len(failed_logins)}`\n")
        file.write(f"- Active remote connections: `{len(connections)}`\n")
        file.write(f"- Listening sockets: `{len(sockets)}`\n\n")

        file.write("## Sources\n\n")
        for source in sources:
            file.write(f"- `{source}`\n")
        file.write("\n")

        file.write("## Alerts\n\n")
        if alerts:
            for alert in alerts:
                file.write(f"### {alert.severity} — {alert.category}\n\n")
                file.write(f"- IP: `{alert.ip}`\n")
                file.write(f"- Message: {alert.message}\n\n")
        else:
            file.write("No suspicious authentication activity matched the current rules.\n\n")

        file.write("## Top IP addresses in logs\n\n")
        if top_ips:
            for ip, count in top_ips:
                file.write(f"- `{ip}` — {count} occurrence(s)\n")
        else:
            file.write("No external IPv4 addresses were found in the collected logs.\n")
        file.write("\n")

        file.write("## Recent successful logins\n\n")
        for record in successful_logins:
            file.write(f"- User `{record.username}` from `{record.ip}` — `{record.raw}`\n")
        file.write("\n")

        file.write("## Recent failed logins\n\n")
        for record in failed_logins:
            file.write(f"- User `{record.username}` from `{record.ip}` — `{record.raw}`\n")
        file.write("\n")

        file.write("## Current active remote connections\n\n")
        for item in connections:
            file.write(
                f"- `{item.netid}` `{item.state}` | "
                f"Local: `{item.local}` | Remote: `{item.remote}` | Process: `{item.process}`\n"
            )
        file.write("\n")

        file.write("## Listening sockets\n\n")
        for item in sockets:
            file.write(
                f"- `{item.netid}` `{item.state}` | "
                f"Local: `{item.local_address}` | Process: `{item.process}`\n"
            )
