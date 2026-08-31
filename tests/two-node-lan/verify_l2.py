#!/usr/bin/env python3
"""Inject and capture Ethernet traffic across two Stella TAP clients."""

from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path

from scapy.all import ARP, Ether, IP, UDP, AsyncSniffer, Raw, sendp


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left-interface", required=True)
    parser.add_argument("--right-interface", required=True)
    parser.add_argument("--left-mac", required=True)
    parser.add_argument("--right-mac", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def normalize_mac(value: str) -> str:
    return value.replace("-", ":").lower()


def transfer(
    source_interface: str,
    destination_interface: str,
    packet,
    predicate,
    timeout: float,
) -> bool:
    sniffer = AsyncSniffer(
        iface=destination_interface,
        store=True,
        lfilter=predicate,
        timeout=timeout,
    )
    sniffer.start()
    time.sleep(0.4)
    sendp(packet, iface=source_interface, count=3, inter=0.15, verbose=False)
    sniffer.join()
    packets = sniffer.results
    return any(predicate(candidate) for candidate in packets)


def raw_marker(marker: bytes):
    return lambda packet: packet.haslayer(Raw) and bytes(packet[Raw].load) == marker


def main() -> int:
    args = arguments()
    left_mac = normalize_mac(args.left_mac)
    right_mac = normalize_mac(args.right_mac)
    nonce = secrets.token_hex(8).encode("ascii")
    results: list[dict[str, object]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        results.append({"name": name, "passed": passed, "detail": detail})

    arp_request = Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=left_mac,
        psrc="10.77.0.1",
        hwdst="00:00:00:00:00:00",
        pdst="10.77.0.2",
    )
    record(
        "ARP request A to B",
        transfer(
            args.left_interface,
            args.right_interface,
            arp_request,
            lambda packet: packet.haslayer(ARP)
            and packet[ARP].op == 1
            and packet[ARP].psrc == "10.77.0.1"
            and packet[ARP].pdst == "10.77.0.2",
            args.timeout,
        ),
        "Ethernet broadcast ARP request crossed the encrypted peer path",
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
        transfer(
            args.right_interface,
            args.left_interface,
            arp_reply,
            lambda packet: packet.haslayer(ARP)
            and packet[ARP].op == 2
            and packet[ARP].psrc == "10.77.0.2"
            and packet[ARP].pdst == "10.77.0.1",
            args.timeout,
        ),
        "Directed ARP reply crossed the reverse peer path",
    )

    unicast_ab = b"STELLA_IPV4_A_TO_B_" + nonce
    record(
        "IPv4 unicast A to B",
        transfer(
            args.left_interface,
            args.right_interface,
            Ether(src=left_mac, dst=right_mac)
            / IP(src="10.77.0.1", dst="10.77.0.2")
            / UDP(sport=31001, dport=31002)
            / Raw(unicast_ab),
            raw_marker(unicast_ab),
            args.timeout,
        ),
        "Directed IPv4 payload crossed from A to B",
    )

    unicast_ba = b"STELLA_IPV4_B_TO_A_" + nonce
    record(
        "IPv4 unicast B to A",
        transfer(
            args.right_interface,
            args.left_interface,
            Ether(src=right_mac, dst=left_mac)
            / IP(src="10.77.0.2", dst="10.77.0.1")
            / UDP(sport=31002, dport=31001)
            / Raw(unicast_ba),
            raw_marker(unicast_ba),
            args.timeout,
        ),
        "Directed IPv4 payload crossed from B to A",
    )

    broadcast = b"STELLA_IPV4_BROADCAST_" + nonce
    record(
        "IPv4 broadcast",
        transfer(
            args.left_interface,
            args.right_interface,
            Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="10.77.0.1", dst="10.77.0.255")
            / UDP(sport=31100, dport=31100)
            / Raw(broadcast),
            raw_marker(broadcast),
            args.timeout,
        ),
        "Limited LAN broadcast reached the other TAP",
    )

    multicast = b"STELLA_IPV4_MULTICAST_" + nonce
    record(
        "IPv4 multicast",
        transfer(
            args.left_interface,
            args.right_interface,
            Ether(src=left_mac, dst="01:00:5e:01:02:03")
            / IP(src="10.77.0.1", dst="239.1.2.3")
            / UDP(sport=31200, dport=31200)
            / Raw(multicast),
            raw_marker(multicast),
            args.timeout,
        ),
        "IPv4 multicast Ethernet frame reached the other TAP",
    )

    discovery_query = b"STELLA_LAN_DISCOVER_QUERY_" + nonce
    query_ok = transfer(
        args.left_interface,
        args.right_interface,
        Ether(src=left_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="10.77.0.1", dst="255.255.255.255")
        / UDP(sport=31301, dport=31300)
        / Raw(discovery_query),
        raw_marker(discovery_query),
        args.timeout,
    )
    discovery_reply = b"STELLA_LAN_DISCOVER_REPLY_" + nonce
    reply_ok = transfer(
        args.right_interface,
        args.left_interface,
        Ether(src=right_mac, dst=left_mac)
        / IP(src="10.77.0.2", dst="10.77.0.1")
        / UDP(sport=31300, dport=31301)
        / Raw(discovery_reply),
        raw_marker(discovery_reply),
        args.timeout,
    )
    record(
        "Broadcast LAN discovery",
        query_ok and reply_ok,
        "Broadcast discovery query and directed discovery response both crossed Stella",
    )

    report = {
        "left_interface": args.left_interface,
        "right_interface": args.right_interface,
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
