from .models import ListeningSocket, RemoteConnection
from .settings import IP_RE
from .sources import run_command


def active_remote_connections(limit: int) -> list[RemoteConnection]:
    lines, error = run_command(["ss", "-tunap"], timeout=15)

    if error or not lines:
        return []

    connections = []

    for line in lines:
        if line.startswith("Netid") or not line.strip():
            continue

        parts = line.split()

        if len(parts) < 6:
            continue

        netid = parts[0]
        state = parts[1]
        local = parts[4]
        remote = parts[5]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""

        ips = IP_RE.findall(remote)

        if not ips:
            continue

        ip = ips[0]

        if ip.startswith(("127.", "0.")):
            continue

        connections.append(
            RemoteConnection(
                netid=netid,
                state=state,
                local=local,
                remote=remote,
                ip=ip,
                process=process
            )
        )

    return connections[:limit]


def listening_sockets(limit: int) -> list[ListeningSocket]:
    lines, error = run_command(["ss", "-tulpen"], timeout=15)

    if error or not lines:
        return []

    sockets = []

    for line in lines:
        if line.startswith("Netid") or not line.strip():
            continue

        parts = line.split()

        if len(parts) < 6:
            continue

        netid = parts[0]
        state = parts[1]
        local_address = parts[4]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""

        sockets.append(
            ListeningSocket(
                netid=netid,
                state=state,
                local_address=local_address,
                process=process
            )
        )

    return sockets[:limit]
