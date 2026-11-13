import time 
with open("netscope/experiments/capture.pcap", "rb") as file:
    global_header = file.read(24)

    if len(global_header) != 24:
        raise ValueError("Invalid PCAP header")

    magic = global_header[0:4]

    if magic == bytes.fromhex("d4c3b2a1"):
        byte_order = "little"
        timestamp_resolution = "microseconds"

    elif magic == bytes.fromhex("a1b2c3d4"):
        byte_order = "big"
        timestamp_resolution = "microseconds"

    elif magic == bytes.fromhex("4d3cb2a1"):
        byte_order = "little"
        timestamp_resolution = "nanoseconds"

    elif magic == bytes.fromhex("a1b23c4d"):
        byte_order = "big"
        timestamp_resolution = "nanoseconds"

    else:
        raise ValueError("Not a supported classic PCAP file")

    linktype = int.from_bytes(global_header[20:24], byteorder=byte_order)
    
    
    snaplen = int.from_bytes(global_header[16:20], byteorder=byte_order)

    packet_count = 0
    flows = {}
    while True:
            packet_header = file.read(16)

            if packet_header == b"": #end of file
                break

            if len(packet_header) != 16:
                raise ValueError("Incomplete packet header")

            ts_sec = int.from_bytes(packet_header[0:4], byteorder=byte_order)
            ts_fraction = int.from_bytes(packet_header[4:8], byteorder=byte_order)
            incl_len = int.from_bytes(packet_header[8:12], byteorder=byte_order)
            orig_len = int.from_bytes(packet_header[12:16], byteorder=byte_order)

            if incl_len > snaplen or incl_len > orig_len: 
                raise ValueError("Invalid packet length")

            packet_data = file.read(incl_len)

            if len(packet_data) != incl_len:
                raise ValueError("Incomplete packet data")

            packet_count += 1

            if linktype == 0:
                if len(packet_data) < 4:
                    raise ValueError("Invalid loopback header")

                family = int.from_bytes(packet_data[0:4], byteorder=byte_order)

                if family != 2: #ip v4 
                    continue

                ip_data = packet_data[4:]

            elif linktype == 101:
                ip_data = packet_data

            else:
                raise ValueError("Unsupported LinkType")

            if len(ip_data) < 1:
                raise ValueError("Missing IP header")

            version = ip_data[0] // 16# split the first byte into version and IHL
            if version != 4: #v4 only
                continue

            if len(ip_data) < 20:
                raise ValueError("Incomplete IPv4 header")
            
          
            ihl = ip_data[0] % 16
            header_length = ihl * 4

            if ihl < 5 or len(ip_data) < header_length:
                raise ValueError("Invalid IPv4 header")

            total_length = int.from_bytes(ip_data[2:4], "big")

            if total_length < header_length:
                raise ValueError("Invalid IP total length")

            protocol = ip_data[9]

            if protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            else:
                protocol_name = "Other"

            source_port = None
            destination_port = None

            if protocol == 6 or protocol == 17:
                if total_length < header_length + 4 or len(ip_data) < header_length + 4:
                    raise ValueError("Incomplete transport header")

                source_port = int.from_bytes(ip_data[header_length:header_length+2], "big")
                destination_port = int.from_bytes(ip_data[header_length+2:header_length+4], "big")
 
            source_ip = ".".join(str(b) for b in ip_data[12:16])
            destination_ip = ".".join(str(b) for b in ip_data[16:20])

            if source_port is not None and destination_port is not None:
                key = (source_ip, destination_ip, source_port, destination_port, protocol)
                reverse_key = (destination_ip, source_ip, destination_port, source_port, protocol)

                if key in flows:
                    flow_key = key
                elif reverse_key in flows:
                    flow_key = reverse_key
                else:
                    flow_key = key
                    flows[flow_key] = {"packets": 0, "bytes": 0}

                flows[flow_key]["packets"] += 1
                flows[flow_key]["bytes"] += total_length


            if timestamp_resolution == "microseconds":
             timestamp = ts_sec + ts_fraction / 1_000_000
            else:
                timestamp = ts_sec + ts_fraction / 1_000_000_000

    
            print("Packet:", packet_count)
            print("IP Version:", version)
            print("Timestamp:", timestamp)
            print("Captured Length:", incl_len)
            print("Original Length:", orig_len)
            print("Total Length:", total_length)
            print("Header Length:", header_length)

            print("Protocol:", protocol_name)
            print("Source IP:", source_ip)
            print("Destination IP:", destination_ip)
            print("Source Port:", source_port)
            print("Destination Port:", destination_port)
    print("Total Packets:", packet_count)
    print("Total Flows:", len(flows))

    for key, stats in flows.items():
        print("Flow:", key)
        print("Packets:", stats["packets"])
        print("Bytes:", stats["bytes"])