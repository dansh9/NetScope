import psutil
import socket
import time


POLL_TIME = 5


def format_address(address):
    if not address:
        return "None"

    if ":" in address.ip:
        return f"[{address.ip}]:{address.port}"

    return f"{address.ip}:{address.port}"


def get_process_name(pid):
    if pid is None:
        return "Unknown"
    if pid == 0:
        return "Unassigned/System"
    try:
        process = psutil.Process(pid)
        return process.name()

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"


def get_ip_version(family):
    if family == socket.AF_INET:
        return "IPv4"

    if family == socket.AF_INET6:
        return "IPv6"

    return "Unknown"


def get_protocol(socket_type):
    if socket_type == socket.SOCK_STREAM:
        return "TCP"

    if socket_type == socket.SOCK_DGRAM:
        return "UDP"

    return "Unknown"


def get_address_parts(address):
    if not address:
        return None, None

    return address.ip, address.port


def make_connection_key(connection):
    local_ip, local_port = get_address_parts(connection.laddr)
    remote_ip, remote_port = get_address_parts(connection.raddr)

    return (
        connection.family,
        connection.type,
        local_ip,
        local_port,
        remote_ip,
        remote_port
    )

def should_display(metadata):
    if metadata["pid"] in (None, 0):
        return False

    if metadata["status"] == "TIME_WAIT":
        return False

    return True
def make_snapshot():
    snapshot = {}

    connections = psutil.net_connections(kind="inet")

    for connection in connections:
        protocol = get_protocol(connection.type)

        if protocol != "TCP":
            continue

        key = make_connection_key(connection)

        snapshot[key] = {
            "pid": connection.pid,
            "process_name": get_process_name(connection.pid),
            "status": connection.status,
            "ip_version": get_ip_version(connection.family),
            "protocol": protocol,
            "local_address": format_address(connection.laddr),
            "remote_address": format_address(connection.raddr)
        }

    return snapshot


previous_snapshot = make_snapshot()

while True:
    time.sleep(POLL_TIME)

    current_snapshot = make_snapshot()

    previous_keys = previous_snapshot.keys()
    current_keys = current_snapshot.keys()

    new_connections = current_keys - previous_keys
    disappeared_connections = previous_keys - current_keys

    existing_connections = current_keys & previous_keys

    for key in new_connections:
        metadata = current_snapshot[key]
        if not should_display(metadata):
            continue
        print()
        print("[NEW]")
        print("Process:", metadata["process_name"])
        print("PID:", metadata["pid"])
        print("IP version:", metadata["ip_version"])
        print("Protocol:", metadata["protocol"])
        print("Local:", metadata["local_address"])
        print("Remote:", metadata["remote_address"])
        print("Status:", metadata["status"])

    for key in disappeared_connections:
        metadata = previous_snapshot[key]
        if not should_display(metadata):
            continue

        print()
        print("[DISAPPEARED]")
        print("Process:", metadata["process_name"])
        print("PID:", metadata["pid"])
        print("Protocol:", metadata["protocol"])
        print("Local:", metadata["local_address"])
        print("Remote:", metadata["remote_address"])
        print("Last status:", metadata["status"])

    for key in existing_connections:
        previous_metadata = previous_snapshot[key]
        current_metadata = current_snapshot[key]

        previous_status = previous_metadata["status"]
        current_status = current_metadata["status"]

        if previous_status != current_status:
            if not should_display(current_metadata):
                continue

            print()
            print("[STATE CHANGED]")
            print("Process:", current_metadata["process_name"])
            print("PID:", current_metadata["pid"])
            print("Protocol:", current_metadata["protocol"])
            print("Local:", current_metadata["local_address"])
            print("Remote:", current_metadata["remote_address"])
            print(
                "Status:",
                previous_status,
                "->",
                current_status
            )

    previous_snapshot = current_snapshot