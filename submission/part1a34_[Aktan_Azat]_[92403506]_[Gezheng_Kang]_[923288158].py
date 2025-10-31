import dpkt
import dpkt.http
import socket
from datetime import datetime, timezone
from pathlib import Path

PCAP_DIR = Path(__file__).resolve().parent.parent / "wireshark-files"


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


if __name__ == "__main__":
    ping_dests = []
    example_dests = []
    httpforever_dests = []
    tmz_dests = []
    ftp_dests = []
    ssh_dests = []

    example_info = None
    httpforever_info = None
    tmz_info = None

    with (PCAP_DIR / "part-1-google-ping.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            icmp = ip.data
            if isinstance(icmp, dpkt.icmp.ICMP) and icmp.type == dpkt.icmp.ICMP_ECHO:
                dest = socket.inet_ntoa(ip.dst)
                if dest not in seen:
                    ping_dests.append((dest, iso(ts)))
                    seen.add(dest)

    with (PCAP_DIR / "part-2-example-com.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport in (80, 443):
                dest = socket.inet_ntoa(ip.dst)
                if dest not in seen:
                    example_dests.append((dest, iso(ts)))
                    seen.add(dest)
            if example_info is None and tcp.dport == 80 and tcp.data:
                if tcp.data.startswith((b"GET ", b"POST ", b"HEAD ")):
                    req = dpkt.http.Request(tcp.data)
                    host = req.headers.get("host", "")
                    if host.endswith("example.com"):
                        example_info = (socket.inet_ntoa(ip.dst), iso(ts), req.headers.get("user-agent", ""))

    with (PCAP_DIR / "part-3-http-forever-com.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport == 80:
                dest = socket.inet_ntoa(ip.dst)
                if dest not in seen:
                    httpforever_dests.append((dest, iso(ts)))
                    seen.add(dest)
                if httpforever_info is None and tcp.data:
                    if tcp.data.startswith((b"GET ", b"POST ", b"HEAD ")):
                        req = dpkt.http.Request(tcp.data)
                        host = req.headers.get("host", "")
                        if host.endswith("httpforever.com"):
                            httpforever_info = (dest, iso(ts), req.headers.get("user-agent", ""))

    with (PCAP_DIR / "part-4-tmz-com.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport == 443:
                dest = socket.inet_ntoa(ip.dst)
                if dest not in seen:
                    tmz_dests.append((dest, iso(ts)))
                    seen.add(dest)
            if tmz_info is None and tcp.dport == 80 and tcp.data:
                if tcp.data.startswith((b"GET ", b"POST ", b"HEAD ")):
                    req = dpkt.http.Request(tcp.data)
                    host = req.headers.get("host", "")
                    if "tmz.com" in host:
                        tmz_info = (socket.inet_ntoa(ip.dst), iso(ts), req.headers.get("user-agent", ""))

    ftp_first = None
    ftp_first_ts = None
    with (PCAP_DIR / "part-5-ftp-anonymous-login.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if ftp_first is None:
                ftp_first = socket.inet_ntoa(ip.dst)
                ftp_first_ts = iso(ts)
            if tcp.dport == 21:
                dest = socket.inet_ntoa(ip.dst)
                if dest not in seen:
                    ftp_dests.append((dest, iso(ts)))
                    seen.add(dest)

    if not ftp_dests and ftp_first:
        ftp_dests.append((ftp_first, ftp_first_ts))

    ssh_first = None
    ssh_first_ts = None
    with (PCAP_DIR / "part-6-ssh.pcap").open("rb") as f:
        seen = set()
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if ssh_first is None:
                ssh_first = socket.inet_ntoa(ip.dst)
                ssh_first_ts = iso(ts)
            if tcp.dport == 22:
                addr = socket.inet_ntoa(ip.dst)
            elif tcp.sport == 22:
                addr = socket.inet_ntoa(ip.src)
            else:
                continue
            if addr not in seen:
                ssh_dests.append((addr, iso(ts)))
                seen.add(addr)

    if not ssh_dests and ssh_first:
        ssh_dests.append((ssh_first, ssh_first_ts))

    rows = [
        ("Ping google.com", ping_dests),
        ("Visit example.com", example_dests),
        ("Visit httpforever.com", httpforever_dests),
        ("Visit tmz.com", tmz_dests),
        ("FTP anonymous login", ftp_dests),
        ("SSH session", ssh_dests),
    ]

    print("Q3: All unique destinations per activity")
    for label, entries in rows:
        if entries:
            first_addr, first_ts = entries[0]
            print(f"{label:23} -> {first_addr:15} {first_ts}")
            for addr, ts in entries[1:]:
                print(f"{'':23}    {addr:15} {ts}")
        else:
            print(f"{label:23} -> (not found)")

    print("\nQ4: Browser fingerprints")
    ua_rows = [
        ("Visit example.com", example_info[2] if example_info else None),
        ("Visit httpforever.com", httpforever_info[2] if httpforever_info else None),
        ("Visit tmz.com", tmz_info[2] if tmz_info else None),
    ]
    for label, value in ua_rows:
        text = value if value else "Not visible (encrypted TLS only)"
        print(f"{label:23} -> {text}")

    if httpforever_info and httpforever_info[2]:
        print(f"\nObserved User-Agent for httpforever.com: {httpforever_info[2]}")
