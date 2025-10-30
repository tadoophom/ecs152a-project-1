import dpkt
import socket
from datetime import datetime, timezone
from pathlib import Path

pcap_dir = Path(__file__).resolve().parent / "wireshark-files"


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


if __name__ == "__main__":
    rows = []

    # Ping google.com
    ping_result = None
    f = open(pcap_dir / "part-1-google-ping.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                if icmp.type == dpkt.icmp.ICMP_ECHO:
                    ping_result = (socket.inet_ntoa(ip.dst), iso(ts))
                    break
    f.close()
    rows.append(("Ping google.com", ping_result))

    # Visit example.com
    example_result = None
    f = open(pcap_dir / "part-2-example-com.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if example_result is None:
                example_result = (socket.inet_ntoa(ip.dst), iso(ts))
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and tcp.dport == 80 and (tcp.flags & dpkt.tcp.TH_SYN):
                example_result = (socket.inet_ntoa(ip.dst), iso(ts))
                break
    f.close()
    rows.append(("Visit example.com", example_result))

    # Visit httpforever.com
    httpforever_result = None
    httpforever_ua = None
    f = open(pcap_dir / "part-3-http-forever-com.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and tcp.dport == 80 and tcp.data:
                try:
                    req = dpkt.http.Request(tcp.data)
                except (dpkt.UnpackError, ValueError):
                    continue
                host = req.headers.get("host", "")
                if host.endswith("httpforever.com"):
                    httpforever_result = (socket.inet_ntoa(ip.dst), iso(ts))
                    httpforever_ua = req.headers.get("user-agent", "")
                    break
    f.close()
    rows.append(("Visit httpforever.com", httpforever_result))

    # Visit tmz.com (DNS)
    tmz_result = None
    f = open(pcap_dir / "part-4-tmz-com.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            udp = ip.data
            if isinstance(udp, dpkt.udp.UDP) and (udp.sport == 53 or udp.dport == 53):
                try:
                    dns = dpkt.dns.DNS(udp.data)
                except (dpkt.UnpackError, ValueError):
                    continue
                if not dns.qr or dns.rcode:
                    continue
                qnames = []
                for q in dns.qd:
                    name = q.name.decode("utf-8", "ignore") if isinstance(q.name, bytes) else q.name
                    qnames.append(name.lower())
                target = None
                for candidate in ("static.tmz.com", "www.tmz.com"):
                    if candidate in qnames:
                        target = candidate
                        break
                if target is None:
                    continue
                for ans in dns.an:
                    if ans.type == dpkt.dns.DNS_A:
                        ans_name = ans.name.decode("utf-8", "ignore") if isinstance(ans.name, bytes) else ans.name
                        if ans_name.lower() == target:
                            tmz_result = (socket.inet_ntoa(ans.rdata), iso(ts))
                            break
                if tmz_result:
                    break
    f.close()
    rows.append(("Visit tmz.com", tmz_result))

    # FTP anonymous login
    ftp_anon_result = None
    f = open(pcap_dir / "part-5-ftp-anonymous-login.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if ftp_anon_result is None:
                ftp_anon_result = (socket.inet_ntoa(ip.dst), iso(ts))
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and tcp.dport == 21 and (tcp.flags & dpkt.tcp.TH_SYN):
                ftp_anon_result = (socket.inet_ntoa(ip.dst), iso(ts))
                break
    f.close()
    rows.append(("FTP anonymous login", ftp_anon_result))

    # SSH session
    ssh_result = None
    f = open(pcap_dir / "part-6-ssh.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if ssh_result is None:
                ssh_result = (socket.inet_ntoa(ip.dst), iso(ts))
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP):
                if tcp.dport == 22 and (tcp.flags & dpkt.tcp.TH_SYN):
                    ssh_result = (socket.inet_ntoa(ip.dst), iso(ts))
                    break
                if tcp.sport == 22 and (tcp.flags & dpkt.tcp.TH_SYN):
                    ssh_result = (socket.inet_ntoa(ip.src), iso(ts))
                    break
    f.close()
    rows.append(("SSH session", ssh_result))

    print("Q3: First destination per activity")
    for label, result in rows:
        if result:
            print(f"{label:23} -> {result[0]:15} {result[1]}")
        else:
            print(f"{label:23} -> (not found)")

    example_ua = None
    f = open(pcap_dir / "part-2-example-com.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and tcp.dport == 80 and tcp.data:
                try:
                    req = dpkt.http.Request(tcp.data)
                except (dpkt.UnpackError, ValueError):
                    continue
                if req.headers.get("host", "").endswith("example.com"):
                    example_ua = req.headers.get("user-agent", "")
                    break
    f.close()

    tmz_ua = None
    f = open(pcap_dir / "part-4-tmz-com.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for ts, data in pcap:
        eth = dpkt.ethernet.Ethernet(data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and tcp.dport == 80 and tcp.data:
                try:
                    req = dpkt.http.Request(tcp.data)
                except (dpkt.UnpackError, ValueError):
                    continue
                if "tmz.com" in req.headers.get("host", ""):
                    tmz_ua = req.headers.get("user-agent", "")
                    break
    f.close()

    print("\nQ4: Browser fingerprints")
    ua_rows = [
        ("Visit example.com", example_ua),
        ("Visit httpforever.com", httpforever_ua),
        ("Visit tmz.com", tmz_ua),
    ]
    for label, value in ua_rows:
        text = value if value else "Not visible (encrypted TLS only)"
        print(f"{label:23} -> {text}")

    if httpforever_ua:
        print(f"\nObserved User-Agent for httpforever.com: {httpforever_ua}")
