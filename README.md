# Stella

## Overview
Stella is an experimental and learning-purpose virtual Ethernet switch designed to create a layer 2 network tunnel over the internet. It enables traditional LAN-based applications, such as multiplayer games that rely on broadcast/multicast discovery, to work seamlessly across different physical networks.

## Purpose
The primary goal of Stella is to allow software developers and gaming enthusiasts to connect with friends in different physical locations as if they were on the same local network. Unlike many existing VPN solutions that operate at layer 3, Stella focuses on providing a true layer 2 network experience, preserving broadcast and multicast capabilities essential for many legacy applications and games.

## Key Features
- Layer 2 network emulation across the internet
- Support for broadcast and multicast traffic
- Central controller for node discovery and connection management
- Peer-to-peer connection establishment with fallback to server relay
- Virtual network interface creation (TUN/TAP)

## Technology
Stella works by creating virtual network interfaces on participating machines and forwarding Ethernet frames between them. It uses a central controller for initial node discovery and can establish direct peer-to-peer connections when possible, with server relay as a fallback for NAT traversal issues.

## Development Status
This project is in early development stages and is intended primarily for educational purposes. Features are being added incrementally, starting with basic connectivity and expanding to include more advanced capabilities.

## License
This project is licensed under the Mozilla Public License 2.0 (MPL 2.0). See the [LICENSE](LICENSE) file for details.

## Disclaimer
This is an experimental project and should not be relied upon for production use or critical networking applications. Security and performance optimizations are ongoing.