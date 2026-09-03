#!/usr/bin/env python3
"""Verify one real Windows TAP client against a headless Stella peer."""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import time
from pathlib import Path
from threading import Event
from typing import Callable

from scapy.all import ARP, Ether, IP, UDP, AsyncSniffer, Raw, sendp


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--left-mac", required=True)
    parser.add_argument("--right-mac", required=True)
    parser.add_argument("--peer-control", default="127.0.0.1:45200")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def normalize_mac(value: str) -> str:
    return value.replace("-", ":").lower()


class PeerControl:
    def __init__(self, address: str, timeout: float) -> None:
        host, port = address.rsplit(":", 1)
        self.socket = socket.create_connection((host, int(port)), timeout=timeout)
        self.socket.settimeout(timeout)
        self.pending_frames: list[Ether] = []

    def close(self) -> None:
        try:
            self._send("QUIT")
        except OSError:
            pass
        self.socket.close()

    def wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self._receive(deadline - time.monotonic())
            if line == "READY":
                return
            self._retain_frame(line)
        raise TimeoutError("headless peer did not establish a Stella session")

    def inject(self, frame: Ether, timeout: float) -> None:
        self._send(f"INJECT {bytes(frame).hex()}")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self._receive(deadline - time.monotonic())
            if line == "OK":
                return
            self._retain_frame(line)
        raise TimeoutError("headless peer did not acknowledge frame injection")

    def wait_for_exactly_one_frame(
        self, predicate: Callable[[Ether], bool], timeout: float
    ) -> bool:
        matches = 0
        remaining_frames: list[Ether] = []
        for frame in self.pending_frames:
            if predicate(frame):
                matches += 1
            else:
                remaining_frames.append(frame)
        self.pending_frames = remaining_frames
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self._receive(deadline - time.monotonic())
            except TimeoutError:
                return matches == 1
            if not line.startswith("FRAME "):
                continue
            frame = Ether(bytes.fromhex(line[6:]))
            if predicate(frame):
                matches += 1
                if matches > 1:
                    return False
                deadline = min(deadline, time.monotonic() + 0.25)
            else:
                self.pending_frames.append(frame)
        return matches == 1

    def _send(self, line: str) -> None:
        self.socket.sendall(line.encode("ascii") + b"\n")

    def _receive(self, timeout: float) -> str:
        self.socket.settimeout(max(timeout, 0.01))
        data = bytearray()
        while True:
            try:
                byte = self.socket.recv(1)
            except socket.timeout as error:
                raise TimeoutError("timed out waiting for headless peer") from error
            if not byte:
                raise ConnectionError("headless peer closed its control connection")
            if byte == b"\n":
                return data.rstrip(b"\r").decode("ascii")
            if len(data) >= 4096:
                raise ValueError("headless peer response exceeded 4096 bytes")
            data.extend(byte)

    def _retain_frame(self, line: str) -> None:
        if line.startswith("FRAME "):
            self.pending_frames.append(Ether(bytes.fromhex(line[6:])))


def remote_transfer(
    peer: PeerControl,
    interface: str,
    packet: Ether,
    predicate: Callable[[Ether], bool],
    timeout: float,
) -> bool:
    sendp(packet, iface=interface, verbose=False)
    return peer.wait_for_exactly_one_frame(predicate, timeout)


def local_transfer(
    peer: PeerControl,
    interface: str,
    packet: Ether,
    predicate: Callable[[Ether], bool],
    timeout: float,
) -> bool:
    ready = Event()
    sniffer = AsyncSniffer(
        iface=interface,
        store=True,
        lfilter=predicate,
        timeout=timeout,
        started_callback=ready.set,
    )
    sniffer.start()
    if not ready.wait(timeout):
        sniffer.join()
        return False
    peer.inject(packet, timeout)
    sniffer.join()
    return sum(predicate(candidate) for candidate in sniffer.results) == 1


def arp_predicate(
    ethernet_source: str,
    ethernet_destination: str,
    operation: int,
    hardware_source: str,
    hardware_destination: str,
    protocol_source: str,
    protocol_destination: str,
) -> Callable[[Ether], bool]:
    return lambda packet: (
        packet.haslayer(Ether)
        and packet.haslayer(ARP)
        and packet[Ether].src.lower() == ethernet_source
        and packet[Ether].dst.lower() == ethernet_destination
        and packet[ARP].op == operation
        and packet[ARP].hwsrc.lower() == hardware_source
        and packet[ARP].hwdst.lower() == hardware_destination
        and packet[ARP].psrc == protocol_source
        and packet[ARP].pdst == protocol_destination
    )


def ipv4_udp_predicate(
    ethernet_source: str,
    ethernet_destination: str,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    marker: bytes,
) -> Callable[[Ether], bool]:
    return lambda packet: (
        packet.haslayer(Ether)
        and packet[Ether].type == 0x0800
        and packet.haslayer(IP)
        and packet.haslayer(UDP)
        and packet.haslayer(Raw)
        and packet[Ether].src.lower() == ethernet_source
        and packet[Ether].dst.lower() == ethernet_destination
        and packet[IP].src == source
        and packet[IP].dst == destination
        and packet[UDP].sport == source_port
        and packet[UDP].dport == destination_port
        and bytes(packet[Raw].load) == marker
    )


def main() -> int:
    args = arguments()
    left_mac = normalize_mac(args.left_mac)
    right_mac = normalize_mac(args.right_mac)
    nonce = secrets.token_hex(8).encode("ascii")
    results: list[dict[str, object]] = []
    peer = PeerControl(args.peer_control, args.timeout)

    def record(name: str, passed: bool, detail: str) -> None:
        results.append({"name": name, "passed": passed, "detail": detail})

    try:
        peer.wait_ready(max(args.timeout, 15.0))

        arp_request = Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=left_mac,
            psrc="10.77.0.1",
            hwdst="00:00:00:00:00:00",
            pdst="10.77.0.2",
        )
        record(
            "ARP request A to B",
            remote_transfer(
                peer,
                args.interface,
                arp_request,
                arp_predicate(
                    left_mac,
                    "ff:ff:ff:ff:ff:ff",
                    1,
                    left_mac,
                    "00:00:00:00:00:00",
                    "10.77.0.1",
                    "10.77.0.2",
                ),
                args.timeout,
            ),
            "Ethernet broadcast ARP request crossed from the Windows TAP to the headless peer",
        )

        arp_reply = Ether(src=right_mac, dst=left_mac) / ARP(
            op=2,
            hwsrc=right_mac,
            psrc="10.77.0.2",
            hwdst=left_mac,
            pdst="10.77.0.1",
        )
        record(
            "ARP reply B to A",
            local_transfer(
                peer,
                args.interface,
                arp_reply,
                arp_predicate(
                    right_mac,
                    left_mac,
                    2,
                    right_mac,
                    left_mac,
                    "10.77.0.2",
                    "10.77.0.1",
                ),
                args.timeout,
            ),
            "Directed ARP reply crossed from the headless peer to the Windows TAP",
        )

        unicast_ab = b"STELLA_IPV4_A_TO_B_" + nonce
        record(
            "IPv4 unicast A to B",
            remote_transfer(
                peer,
                args.interface,
                Ether(src=left_mac, dst=right_mac)
                / IP(src="10.77.0.1", dst="10.77.0.2")
                / UDP(sport=31001, dport=31002)
                / Raw(unicast_ab),
                ipv4_udp_predicate(
                    left_mac,
                    right_mac,
                    "10.77.0.1",
                    "10.77.0.2",
                    31001,
                    31002,
                    unicast_ab,
                ),
                args.timeout,
            ),
            "Directed IPv4 payload crossed from the Windows TAP to the headless peer",
        )

        unicast_ba = b"STELLA_IPV4_B_TO_A_" + nonce
        record(
            "IPv4 unicast B to A",
            local_transfer(
                peer,
                args.interface,
                Ether(src=right_mac, dst=left_mac)
                / IP(src="10.77.0.2", dst="10.77.0.1")
                / UDP(sport=31002, dport=31001)
                / Raw(unicast_ba),
                ipv4_udp_predicate(
                    right_mac,
                    left_mac,
                    "10.77.0.2",
                    "10.77.0.1",
                    31002,
                    31001,
                    unicast_ba,
                ),
                args.timeout,
            ),
            "Directed IPv4 payload crossed from the headless peer to the Windows TAP",
        )

        broadcast = b"STELLA_IPV4_BROADCAST_" + nonce
        record(
            "IPv4 broadcast",
            remote_transfer(
                peer,
                args.interface,
                Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="10.77.0.1", dst="10.77.0.255")
                / UDP(sport=31100, dport=31100)
                / Raw(broadcast),
                ipv4_udp_predicate(
                    left_mac,
                    "ff:ff:ff:ff:ff:ff",
                    "10.77.0.1",
                    "10.77.0.255",
                    31100,
                    31100,
                    broadcast,
                ),
                args.timeout,
            ),
            "IPv4 LAN broadcast reached the headless peer",
        )

        multicast = b"STELLA_IPV4_MULTICAST_" + nonce
        record(
            "IPv4 multicast",
            remote_transfer(
                peer,
                args.interface,
                Ether(src=left_mac, dst="01:00:5e:01:02:03")
                / IP(src="10.77.0.1", dst="239.1.2.3")
                / UDP(sport=31200, dport=31200)
                / Raw(multicast),
                ipv4_udp_predicate(
                    left_mac,
                    "01:00:5e:01:02:03",
                    "10.77.0.1",
                    "239.1.2.3",
                    31200,
                    31200,
                    multicast,
                ),
                args.timeout,
            ),
            "IPv4 multicast Ethernet frame reached the headless peer",
        )

        discovery_query = b"STELLA_LAN_DISCOVER_QUERY_" + nonce
        query_ok = remote_transfer(
            peer,
            args.interface,
            Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="10.77.0.1", dst="255.255.255.255")
            / UDP(sport=31301, dport=31300)
            / Raw(discovery_query),
            ipv4_udp_predicate(
                left_mac,
                "ff:ff:ff:ff:ff:ff",
                "10.77.0.1",
                "255.255.255.255",
                31301,
                31300,
                discovery_query,
            ),
            args.timeout,
        )
        discovery_reply = b"STELLA_LAN_DISCOVER_REPLY_" + nonce
        reply_ok = local_transfer(
            peer,
            args.interface,
            Ether(src=right_mac, dst=left_mac)
            / IP(src="10.77.0.2", dst="10.77.0.1")
            / UDP(sport=31300, dport=31301)
            / Raw(discovery_reply),
            ipv4_udp_predicate(
                right_mac,
                left_mac,
                "10.77.0.2",
                "10.77.0.1",
                31300,
                31301,
                discovery_reply,
            ),
            args.timeout,
        )
        record(
            "Broadcast LAN discovery",
            query_ok and reply_ok,
            "Broadcast discovery query and directed response both crossed Stella",
        )
    finally:
        peer.close()

    report = {
        "verification_mode": "one Windows TAP plus headless Stella peer",
        "left_interface": args.interface,
        "right_interface": "headless Stella peer",
        "left_mac": left_mac,
        "right_mac": right_mac,
        "checks": results,
        "passed": all(bool(result["passed"]) for result in results),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"{status}: {result['name']} - {result['detail']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
