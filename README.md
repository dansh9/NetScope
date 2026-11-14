# NetScope

A learning-focused Python project for investigating how network traffic relates to operating-system sockets and processes.

**Goal:** connect the concepts of **Process → Socket → Connection → Network Traffic** by building and inspecting small, reproducible examples. This is an educational CLI project, not an antivirus, IDS, or production security monitor.

## What is implemented

- **Controlled TCP and UDP traffic:** loopback client/server examples in `experiments/`, with predictable messages and ports.
- **Live TCP connection inspection:** `src/connection_inspector.py` uses `psutil.net_connections(kind="inet")` to take socket snapshots, correlate visible connections with PID/process name, and report new, disappeared, and state-changed connections.
- **IPv4 and IPv6 socket display:** the live inspector handles both address families for TCP connections.
- **Event history:** detected TCP events are appended as JSON Lines in `data/events.jsonl`.
- **Classic PCAP parsing (work in progress):** `src/pcap_reader.py` reads PCAP global/packet headers and basic IPv4, TCP, and UDP fields, groups packets into bidirectional 5-tuple flows, and tries to correlate TCP flows with a current OS socket snapshot.

These are separate working areas of the project; **they are not yet a complete, continuously correlated capture-and-process monitor.**

## Getting started

Requires Python 3 and, for live process inspection, access to socket information provided by the operating system. Some process details may be unavailable without elevated permissions.

```bash
python -m pip install -r requirements.txt
python src/connection_inspector.py
```

The inspector polls every 5 seconds. Stop it with Ctrl+C. The resulting `data/events.jsonl` is generated locally.

For controlled loopback traffic, start a server in one terminal and its corresponding client in another:

```bash
python experiments/tcp_server.py
python experiments/tcp_client.py
```

The UDP example uses `experiments/udp_server.py` and `experiments/udp_client.py` in the same way. See [experiment notes](experiments/README.md).

### PCAP reader: current limitation

The PCAP reader currently opens the hard-coded relative path `netscope/experiments/capture.pcap`; **no capture file is included in this repository**. You must supply a compatible capture at that path (relative to your working directory) or adjust the local path before running `python src/pcap_reader.py`.

It supports classic PCAP files with the implemented loopback/raw-IP link types (0 and 101), not arbitrary Ethernet captures or PCAPNG. It handles IPv4 packet fields, with basic TCP/UDP port extraction; the live socket snapshot remains TCP-only. A socket that closed before the snapshot may not be matchable to a historical packet flow.

## Design decisions and lessons

The project starts with simple TCP/UDP clients and observable OS connections rather than a large interface or a security-product claim. Repeated socket snapshots make connection state changes visible, while raw PCAP parsing exposes what is actually present in packet bytes. The distinction between a **historical packet** and a **current socket** matters: a flow may be valid even when its PID cannot be recovered later.

## Next steps

- Accept a PCAP filename as a command-line argument instead of using a fixed path.
- Improve capture-format support and robustness of packet validation.
- Add explicit tests using small, controlled capture files.
- Refine the limits and accuracy of process-to-flow correlation.
- Consider a GUI only after the core CLI and tests are stable.

## Project status

Actively developed educational prototype. See `src/` and `experiments/` for the current implementation. The README describes implemented features separately from planned work.
