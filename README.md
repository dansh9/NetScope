# NetScope

NetScope is a learning-focused network investigation project.

## Goal

Understand how applications communicate over the network by connecting:

**Process -> Socket -> Connection -> Network Traffic**

The project is designed to build deep practical knowledge of networking, with a secondary focus on operating-system networking.

## Planned core

- TCP/UDP client-server experiments
- Inspect active connections and listening sockets
- Correlate connections with local processes
- Analyze captures with Wireshark
- Parse selected Ethernet / IPv4 / TCP / UDP fields from raw bytes
- Group packets into network flows
- Basic DNS analysis

## Scope

NetScope is **not** intended to be an antivirus, IDS, or malware detector.

The focus is understanding network behavior and being able to explain how every part works.

## Current status

Initial development.

### First milestone

Build a controlled TCP client/server experiment, capture it in Wireshark, and understand the connection before NetScope begins analyzing it.
