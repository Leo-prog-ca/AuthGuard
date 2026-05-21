import os
import subprocess
from pathlib import Path

from .models import LoginRecord
from .settings import AUTH_LOG_FILES, IP_RE


class SourceError(Exception):
    pass


def run_command(command: list[str], timeout: int = 20) -> tuple[list[str], str | None]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except FileNotFoundError:
        return [], f"command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return [], f"command timed out: {' '.join(command)}"
    except OSError as error:
        return [], f"system error: {error}"

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode == 0 and stdout:
        return stdout.splitlines(), None

    return [], stderr or "no output returned"


def read_log_file(path: str) -> tuple[list[str], str]:
    log_path = Path(path)

    if not log_path.exists():
        raise SourceError(f"log file does not exist: {path}")

    if not os.access(log_path, os.R_OK):
        raise SourceError(f"permission denied: {path}")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines(), str(log_path)
    except OSError as error:
        raise SourceError(f"could not read {path}: {error}")


def collect_auth_lines(file_path: str | None, since: str) -> tuple[list[str], list[str], list[str]]:
    lines = []
    sources = []
    notes = []

    if file_path:
        try:
            file_lines, source = read_log_file(file_path)
            return file_lines, [source], notes
        except SourceError as error:
            return [], [], [str(error)]

    for log_file in AUTH_LOG_FILES:
        try:
            file_lines, source = read_log_file(log_file)
            if file_lines:
                lines.extend(file_lines)
                sources.append(source)
        except SourceError as error:
            notes.append(str(error))

    journal_lines, journal_error = run_command(
        ["journalctl", "--since", since, "--no-pager"],
        timeout=30
    )

    if journal_lines:
        cleaned = [
            line for line in journal_lines
            if "No entries" not in line and "-- No entries --" not in line
        ]

        if cleaned:
            lines.extend(cleaned)
            sources.append(f"journalctl --since {since}")

    if journal_error:
        notes.append(f"journalctl: {journal_error}")

    return lines, sources, notes


def read_login_history(limit: int, failed: bool = False) -> list[LoginRecord]:
    command = ["lastb", "-i", "-n", str(limit)] if failed else ["last", "-i", "-n", str(limit)]
    lines, error = run_command(command, timeout=15)

    if error or not lines:
        return []

    records = []

    for line in lines:
        if "wtmp begins" in line or "btmp begins" in line or not line.strip():
            continue

        ips = IP_RE.findall(line)

        if not ips:
            continue

        parts = line.split()
        username = parts[0] if parts else "unknown"

        records.append(
            LoginRecord(
                username=username,
                ip=ips[0],
                raw=line.strip()
            )
        )

    return records
