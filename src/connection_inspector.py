
import psutil
import socket
import time
import json
from pathlib import Path
from datetime import datetime, timezone

POLL_TIME = 5


def format_address(address):
    if not address:
        return "None"

    # IPv6 addresses need to be enclosed in brackets when combined with a port
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

    # Process may close before we get its name
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

    # Connection key without PID and state
    return (
        connection.family,
        connection.type,
        local_ip,
        local_port,
        remote_ip,
        remote_port
    )

def should_display(metadata):
    # Hide connections without a known process
    if metadata["pid"] in (None, 0):
        return False

    if metadata["status"] == "TIME_WAIT":
        return False
    return True

def save_event(event_type, metadata,details=None ):
    timestamp = datetime.now(timezone.utc).isoformat()

    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "metadata": metadata
    }
    if details is not None:
        event["details"] = details

    # Convert event to JSON for logging
    json_line = json.dumps(event)

    # Use project path not current working directory
    data_folder = Path(__file__).resolve().parent.parent / "data"
    data_folder.mkdir(parents=True, exist_ok=True)

    # Append each event as a new line
    with open(data_folder / "events.jsonl", "a", encoding="utf-8") as file:
        file.write(json_line + "\n")

    return event

def make_snapshot():
    snapshot = {}

    # Get current network sockets from the OS
    connections = psutil.net_connections(kind="inet")

    for connection in connections:
        protocol = get_protocol(connection.type)

        # Only TCP connections for now
        if protocol != "TCP":
            continue

        key = make_connection_key(connection)

        # Store process and state information for each key
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

# Run the monitor only when this file is started directly
if __name__ == "__main__":
    previous_snapshot = make_snapshot()

    while True:

        # Wait before taking another snapshot
        time.sleep(POLL_TIME)

        current_snapshot = make_snapshot()

        previous_keys = previous_snapshot.keys()
        current_keys = current_snapshot.keys()

        # Find new and disappeared connections
        new_connections = current_keys - previous_keys
        disappeared_connections = previous_keys - current_keys

        # Connections that exist in both snapshots
        existing_connections = current_keys & previous_keys

        for key in new_connections:
            metadata = current_snapshot[key]
            if not should_display(metadata):
                continue
            print()
            save_event("NEW", metadata)
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
            save_event("DISAPPEARED", metadata)
            print()
            print("[DISAPPEARED]")
            print("Process:", metadata["process_name"])
            print("PID:", metadata["pid"])
            print("Protocol:", metadata["protocol"])
            print("Local:", metadata["local_address"])
            print("Remote:", metadata["remote_address"])
            print("Last status:", metadata["status"])

        # Check if TCP states changed
        for key in existing_connections:
            previous_metadata = previous_snapshot[key]
            current_metadata = current_snapshot[key]

            previous_status = previous_metadata["status"]
            current_status = current_metadata["status"]

            if previous_status != current_status:
                if not should_display(current_metadata):
                    continue

                print()
                save_event("STATE_CHANGED", current_metadata, details={"previous_status": previous_status, "current_status": current_status})
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

        # Save current snapshot for the next comparison
        previous_snapshot = current_snapshot
