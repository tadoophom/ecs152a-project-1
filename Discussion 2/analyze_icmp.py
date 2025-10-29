from __future__ import annotations

import socket
from collections import Counter
from typing import Set, Tuple

import dpkt


ICMP_TYPE_NAMES = {
    0: "echo reply (0)",
    8: "echo request (8)",
    11: "time exceeded (11)",
}


def parse_icmp_packets(
    pcap_path: str,
) -> Tuple[int, Counter[int], Set[str]]:
    type_counts: Counter[int] = Counter()
    time_exceeded_sources: Set[str] = set()
    total_icmp = 0

    with open(pcap_path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.UnpackError, ValueError):
                continue

            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue

            icmp = ip.data
            if not isinstance(icmp, dpkt.icmp.ICMP):
                continue

            total_icmp += 1
            icmp_type = getattr(icmp, "type", None)
            if icmp_type is None:
                continue

            type_counts[icmp_type] += 1

            if icmp_type == dpkt.icmp.ICMP_TIMEXCEED:
                time_exceeded_sources.add(socket.inet_ntoa(ip.src))

    return total_icmp, type_counts, time_exceeded_sources


def main() -> None:
    total_icmp, type_counts, router_sources = parse_icmp_packets(
        "icmp_capture.pcap"
    )

    lines = [f"Total ICMP packets captured: {total_icmp}"]

    if not type_counts:
        lines.append("No ICMP packets found.")
    else:
        for icmp_type, count in sorted(type_counts.items()):
            label = ICMP_TYPE_NAMES.get(icmp_type, f"type {icmp_type}")
            lines.append(f"{label}: {count}")

        if router_sources:
            lines.append("Routers sending time exceeded messages:")
            for ip_str in sorted(router_sources):
                lines.append(f"  {ip_str}")
        else:
            lines.append("Routers sending time exceeded messages: none")

    for line in lines:
        print(line)

    with open("output.txt", "w", encoding="ascii") as outfile:
        outfile.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
