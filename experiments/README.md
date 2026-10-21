# Controlled Traffic Experiments

These small loopback programs generate predictable TCP and UDP traffic for validating NetScope as its inspection and packet-analysis components are developed.

## TCP

`tcp_server.py` and `tcp_client.py` create a TCP connection on `127.0.0.1:6767`.

The client sends two newline-delimited messages and then half-closes its write side. The server buffers the byte stream, extracts complete application messages, and sends a response before closing the connection.

This experiment provides deterministic traffic for inspecting connection state, endpoints, TCP flags, stream framing, and later process-to-flow correlation.

## UDP

`udp_server.py` and `udp_client.py` exchange two datagrams on `127.0.0.1:6768`.

The pair provides controlled UDP traffic for validating datagram boundaries, source/destination endpoints, and later UDP packet and flow parsing.

Both experiments intentionally use loopback so their traffic is isolated and easy to reproduce.
