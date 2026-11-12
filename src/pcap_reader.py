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

            version = ip_data[0] >> 4
            
            if timestamp_resolution == "microseconds":
             timestamp = ts_sec + ts_fraction / 1_000_000
            else:
                timestamp = ts_sec + ts_fraction / 1_000_000_000

    
            print("Packet:", packet_count)
            print("IP Version:", version)
            print("Timestamp:", timestamp)
            print("Captured Length:", incl_len)
            print("Original Length:", orig_len)

    print("Total Packets:", packet_count)
