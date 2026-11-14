# NetScope source

- `connection_inspector.py` polls OS network sockets using `psutil`, displays TCP connection changes, and appends events to `data/events.jsonl`.
- `pcap_reader.py` is an early classic-PCAP/IPv4 parser that summarizes TCP/UDP flows and attempts a one-time match against currently visible TCP sockets.

The PCAP reader currently uses a fixed local file path and limited link types; it is not yet a general-purpose sniffer. For setup, supported formats, and known limitations, see the [project README](../README.md).
