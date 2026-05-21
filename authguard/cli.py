import argparse
import sys

from .auth_parser import parse_linux_auth, top_log_ips
from .network import active_remote_connections, listening_sockets
from .report import print_console_report, write_alerts_csv, write_markdown_report
from .rules import detect_login_anomalies
from .settings import DEFAULT_LIMIT, DEFAULT_SINCE
from .sources import collect_auth_lines, read_login_history


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AuthGuard: Linux security log and connection analyzer"
    )

    parser.add_argument(
        "--file",
        help="read a specific real log file instead of auto-collecting sources"
    )

    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help='journalctl time range, for example "24 hours ago", "today", or "7 days ago"'
    )

    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=5,
        help="number of failed SSH attempts from one IP before alerting"
    )

    parser.add_argument(
        "--user-threshold",
        type=int,
        default=3,
        help="number of invalid usernames from one IP before alerting"
    )

    parser.add_argument(
        "--sudo-threshold",
        type=int,
        default=3,
        help="number of local auth failures before alerting"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="maximum number of records shown in login/network sections"
    )

    parser.add_argument(
        "--csv",
        default="alerts.csv",
        help="path for CSV alert output"
    )

    parser.add_argument(
        "--report",
        default="security_report.md",
        help="path for Markdown report output"
    )

    return parser


def run_cli() -> None:
    args = build_parser().parse_args()

    lines, sources, notes = collect_auth_lines(args.file, args.since)

    events = parse_linux_auth(lines)

    alerts = detect_login_anomalies(
        events=events,
        failed_threshold=args.failed_threshold,
        user_threshold=args.user_threshold,
        sudo_threshold=args.sudo_threshold
    )

    top_ips = top_log_ips(lines, args.limit)
    successful_logins = read_login_history(args.limit, failed=False)
    failed_logins = read_login_history(args.limit, failed=True)
    connections = active_remote_connections(args.limit)
    sockets = listening_sockets(args.limit)

    nothing_to_show = (
        not lines
        and not successful_logins
        and not failed_logins
        and not connections
        and not sockets
    )

    if nothing_to_show:
        print("\nAuthGuard: Linux Security Snapshot")
        print("=" * 60)
        print("Results impossible to retrieve.")
        print("No readable logs, login history, active connections, or listening sockets were available.")
        print("\nTry running:")
        print('sudo python3 main.py --since "24 hours ago"')
        print("=" * 60)
        sys.exit(1)

    print_console_report(
        sources=sources,
        notes=notes,
        line_count=len(lines),
        events=events,
        alerts=alerts,
        top_ips=top_ips,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        connections=connections,
        sockets=sockets,
    )

    write_alerts_csv(alerts, args.csv)

    write_markdown_report(
        path=args.report,
        sources=sources,
        line_count=len(lines),
        events=events,
        alerts=alerts,
        top_ips=top_ips,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        connections=connections,
        sockets=sockets,
    )

    print("\nOutput files:")
    print(f"- CSV: {args.csv}")
    print(f"- Report: {args.report}")
