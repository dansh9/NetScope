import psutil
import socket
def format_address(address):
    if not address:
        return "None"

    if ":" in address.ip:
        return f"[{address.ip}]:{address.port}"

    return f"{address.ip}:{address.port}"
        
def get_process_name(pid):
    if pid is None:
        return "Unknown"

    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"    
def get_ip_version(family):   
    
    if family == socket.AF_INET:
        return "IPv4"
    elif family == socket.AF_INET6:
        return "IPv6"
    return "Unknown"
def get_protocol(socket_type):
    if socket_type == socket.SOCK_STREAM:
        return "TCP"
    elif socket_type == socket.SOCK_DGRAM:
        return "UDP"
    return "Unknown"    
connections = psutil.net_connections(kind="inet")
for connection in connections:
    process_name = get_process_name(connection.pid)

    ip_version = get_ip_version(connection.family)
    connection_type = get_protocol(connection.type)
    print("Connection found:")
    print("Process name:", process_name)
    print("PID:", connection.pid)
    print("IP version:", ip_version)
    print("Protocol:", connection_type)
    print("Local address:", format_address(connection.laddr))
    print("Remote address:", format_address(connection.raddr))
    print("Status:", connection.status)
    print()
