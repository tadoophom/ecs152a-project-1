#!/usr/bin/env python3
"""
Quick-and-simple helpers for ECS 152A Project 1(a) Questions 3 & 4.

Usage:
    python3 pcap_activity_summary.py

The script prints a compact summary of:
  • Destination IPv4 address + first-seen timestamp for each activity PCAP.
  • Browser fingerprints (if visible) for activities 2–4.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

import dpkt

PCAP_DIR = Path(__file__).resolve().parent / "wireshark-files"


def ts_iso(ts: float) -> str:
    """Format a UNIX timestamp as an ISO-8601 UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def first_icmp_echo(pcap_name: str) -> Optional[Tuple[str, str]]:
    """Return first ICMP echo-request destination (IP, timestamp)."""
    path = PCAP_DIR / pcap_name
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for ts, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                if icmp.type == dpkt.icmp.ICMP_ECHO:
                    return socket.inet_ntoa(ip.dst), ts_iso(ts)
    return None


def first_tcp_syn(pcap_name: str, port: int) -> Optional[Tuple[str, str]]:
    """Return first TCP endpoint observed for the given server port (prefer SYN)."""
    path = PCAP_DIR / pcap_name
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        fallback: Optional[Tuple[str, str]] = None
        for ts, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport == port:
                if tcp.flags & dpkt.tcp.TH_SYN:
                    return socket.inet_ntoa(ip.dst), ts_iso(ts)
                if fallback is None:
                    fallback = (socket.inet_ntoa(ip.dst), ts_iso(ts))
            elif tcp.sport == port:
                if tcp.flags & dpkt.tcp.TH_SYN:
                    return socket.inet_ntoa(ip.src), ts_iso(ts)
                if fallback is None:
                    fallback = (socket.inet_ntoa(ip.src), ts_iso(ts))
        return fallback
    return None


def first_http_request(pcap_name: str, host_suffix: str) -> Optional[Tuple[str, str, str]]:
    """Return (dst IP, timestamp, user-agent) for the first HTTP request to host_suffix."""
    path = PCAP_DIR / pcap_name
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for ts, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport != 80 or not tcp.data:
                continue
            try:
                req = dpkt.http.Request(tcp.data)
            except (dpkt.UnpackError, ValueError):
                continue
            host = req.headers.get("host", "")
            if host.endswith(host_suffix):
                dst_ip = socket.inet_ntoa(ip.dst)
                return dst_ip, ts_iso(ts), req.headers.get("user-agent", "")
    return None


def _norm(name: str | bytes) -> str:
    if isinstance(name, bytes):
        return name.decode("utf-8", "ignore").lower()
    return name.lower()


def first_dns_answer(
    pcap_name: str, candidates: Sequence[str]
) -> Optional[Tuple[str, str]]:
    """
    Return first IPv4 answer matching any candidate hostname.

    The candidates are checked in order, so put preferred hostnames first.
    """
    wanted = [c.lower() for c in candidates]
    path = PCAP_DIR / pcap_name
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for ts, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP):
                continue
            if udp.sport != 53 and udp.dport != 53:
                continue
            try:
                dns = dpkt.dns.DNS(udp.data)
            except (dpkt.UnpackError, ValueError):
                continue
            if dns.rcode != dpkt.dns.DNS_RCODE_NOERR or not dns.qr:
                continue
            seen = {_norm(q.name) for q in dns.qd}
            chosen_host = next((host for host in wanted if host in seen), None)
            if not chosen_host:
                continue
            for ans in dns.an:
                if ans.type != dpkt.dns.DNS_A:
                    continue
                if _norm(ans.name) != chosen_host:
                    continue
                return socket.inet_ntoa(ans.rdata), ts_iso(ts)
    return None


def browser_from_http(pcap_name: str, host_suffixes: Iterable[str]) -> Optional[str]:
    """Return the first clear-text User-Agent for hosts ending with host_suffixes."""
    suffixes = tuple(host_suffixes)
    path = PCAP_DIR / pcap_name
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _, buf in reader:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport != 80 or not tcp.data:
                continue
            try:
                req = dpkt.http.Request(tcp.data)
            except (dpkt.UnpackError, ValueError):
                continue
            host = req.headers.get("host", "")
            if host.endswith(suffixes):
                ua = req.headers.get("user-agent")
                if ua:
                    return ua
    return None


def main() -> None:
    httpforever = first_http_request("part-3-http-forever-com.pcap", "httpforever.com")

    q3_rows = [
        ("Ping google.com", first_icmp_echo("part-1-google-ping.pcap")),
        ("Visit example.com", first_tcp_syn("part-2-example-com.pcap", 80)),
        ("Visit httpforever.com", (httpforever[0], httpforever[1]) if httpforever else None),
        ("Visit tmz.com", first_dns_answer("part-4-tmz-com.pcap", ("static.tmz.com", "www.tmz.com"))),
        ("FTP anonymous login", first_tcp_syn("part-5-ftp-anonymous-login.pcap", 21)),
        ("FTP (no login)", first_tcp_syn("part-5-ftp-no-login.pcap", 21)),
        ("SSH session", first_tcp_syn("part-6-ssh.pcap", 22)),
    ]

    print("Q3 – First destination per activity")
    for activity, data in q3_rows:
        if data is None:
            print(f"{activity:25} -> (not found)")
            continue
        ip, ts = data
        print(f"{activity:25} -> {ip:15}  {ts}")

    print("\nQ4 – Browser fingerprints")
    browsers = {
        "Visit example.com": browser_from_http("part-2-example-com.pcap", ("example.com",)),
        "Visit httpforever.com": httpforever[2] if httpforever and httpforever[2] else None,
        "Visit tmz.com": browser_from_http("part-4-tmz-com.pcap", ("tmz.com",)),
    }
    for activity, ua in browsers.items():
        note = ua if ua else "Not visible (encrypted TLS only)"
        print(f"{activity:25} -> {note}")

    if httpforever and httpforever[2]:
        print(f"\nObserved User-Agent for httpforever.com: {httpforever[2]}")


if __name__ == "__main__":
    main()
