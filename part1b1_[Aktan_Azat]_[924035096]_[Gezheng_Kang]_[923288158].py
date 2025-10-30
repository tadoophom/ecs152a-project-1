from datetime import datetime, timezone
import dpkt
import socket
from pathlib import Path

PCAP_PATH = Path(__file__).resolve().parent / "PCAP1" / "PCAP1_1.pcap"


def main() -> None:
    with PCAP_PATH.open("rb") as handle:
        pcap = dpkt.pcap.Reader(handle)

        for timestamp, data in pcap:
            ts = datetime.fromtimestamp(timestamp, timezone.utc)
            eth = dpkt.ethernet.Ethernet(data)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                family = socket.AF_INET
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip = eth.data
                family = socket.AF_INET6
            else:
                continue

            tcp = ip.data

            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            if not tcp.data:
                continue

            if tcp.dport != 80:
                continue

            payload = tcp.data
            payload_lower = payload.lower()

            if b"secret" not in payload_lower and b"flag" not in payload_lower:
                continue

            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            uri_lower = request.uri.lower()
            header_hits = {
                name: value
                for name, value in request.headers.items()
                if "secret" in name.lower() or "secret" in value.lower() or "flag" in value.lower()
            }

            if "secret" not in uri_lower and not header_hits and b"secret" not in request.body.lower():
                continue

            client_ip = socket.inet_ntop(family, ip.src)
            server_ip = socket.inet_ntop(family, ip.dst)

            print("----- Secret-bearing HTTP request -----")
            print(f"Timestamp    : {ts.isoformat()}")
            print(f"Client -> Server: {client_ip} -> {server_ip}")
            print(f"Request line : {request.method} {request.uri}")

            for name, value in header_hits.items():
                print(f"Header       : {name}: {value}")

            if request.body:
                print(f"Body bytes   : {request.body[:80]!r}")

            if not header_hits and "secret" in uri_lower:
                print("Note         : Secret found in request URI.")

            print()


if __name__ == "__main__":
    main()
