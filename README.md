# AuthGuard

AuthGuard is a small Linux security tool written in Python. I built it to practice Linux log analysis, authentication monitoring, and basic host-level security checks on Kali/Linux systems.

The tool collects real local system data and gives a quick security snapshot of the machine. It does not use sample logs and does not upload anything outside the system.

## What it does

AuthGuard checks several local sources:

- authentication logs and system journal entries;
- SSH login events;
- failed authentication attempts;
- invalid username attempts;
- sudo, su, and pkexec authentication failures;
- recent successful login records;
- recent failed login records;
- active remote network connections;
- listening sockets and local services.

The goal is not to replace a SIEM or professional monitoring platform. The project is focused on learning, Linux security practice, and building a simple tool that can give a quick overview of suspicious activity.

## Screenshot

![AuthGuard terminal output](screenshots/authguard-output.png)

## Features

- Reads real Linux/Kali system data
- Uses `journalctl` as a log source
- Parses SSH authentication events
- Detects repeated failed SSH login attempts
- Detects invalid username enumeration
- Detects successful login after multiple failures
- Checks sudo, su, and pkexec authentication failures
- Shows recent successful logins with `last -i`
- Shows recent failed logins with `lastb -i`
- Shows active remote connections with `ss -tunap`
- Shows listening sockets with `ss -tulpen`
- Generates local CSV and Markdown reports

## Project structure

```text
AuthGuard/
├── main.py
├── authguard/
│   ├── auth_parser.py
│   ├── cli.py
│   ├── models.py
│   ├── network.py
│   ├── report.py
│   ├── rules.py
│   ├── settings.py
│   └── sources.py
├── screenshots/
│   └── authguard-output.png
├── requirements.txt
└── README.md
```

## How to run

AuthGuard should be run with `sudo`, because some logs and network details may require elevated permissions.

```bash
sudo python3 main.py --since "7 days ago"
```

You can also change the time range:

```bash
sudo python3 main.py --since "24 hours ago"
```

Or analyze a specific real log file:

```bash
sudo python3 main.py --file /var/log/auth.log
```

## Example output

```text
AuthGuard: Linux Security Snapshot
============================================================
Sources:
- journalctl --since 7 days ago
------------------------------------------------------------
Log lines analyzed: 6900
Authentication events parsed: 1
Alerts: 0
Successful login records: 0
Failed login records: 0
Active remote connections: 7
Listening sockets: 6
============================================================
```

## Output files

After running, AuthGuard creates two local files:

```text
alerts.csv
security_report.md
```

These files are not meant to be uploaded to GitHub, because they may contain real IP addresses, usernames, process names, and system information.

## Security note

AuthGuard runs locally. It does not send logs, IP addresses, reports, or system information to any external server.

The generated reports should be reviewed before sharing. If they include real IP addresses or private system details, they should be removed or masked.

## Limitations

- AuthGuard is not a replacement for SIEM, EDR, IDS, or professional monitoring tools.
- Log parsing is mainly focused on Linux/Kali-style environments.
- Some systems may not have `/var/log/auth.log`.
- Some login history databases may be empty depending on system configuration.
- Network analysis is based on local `ss` command output.
- Detection rules are simple and designed for learning and basic monitoring.

## Tech stack

- Python 3
- Linux system logs
- journalctl
- last / lastb
- ss
- CSV reporting
- Markdown reporting
