import dpkt
import socket
from datetime import datetime, timezone
from pathlib import Path

pcap_path = Path(__file__).resolve().parent / "PCAP1" / "PCAP1_1.pcap"

def url_decode(text: str) -> str:
    result = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "+":
            result.append(" ")
            i += 1
        elif ch == "%" and i + 2 < length:
            hex_part = text[i + 1 : i + 3]
            if all(c in "0123456789abcdefABCDEF" for c in hex_part):
                result.append(chr(int(hex_part, 16)))
            else:
                result.append("%" + hex_part)
            i += 3
        else:
            result.append(ch)
            i += 1
    return "".join(result)


COMMON = {
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "cache-control",
}


if __name__ == "__main__":
    with open(pcap_path, "rb") as handle:
        for ts, data in dpkt.pcap.Reader(handle):
            eth = dpkt.ethernet.Ethernet(data)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip = eth.data
                src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                continue

            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
                continue

            data_bytes = tcp.data
            if not (
                   data_bytes.startswith(b"GET ")
                or data_bytes.startswith(b"POST ")
                or data_bytes.startswith(b"PUT ")
                or data_bytes.startswith(b"DELETE ")
                or data_bytes.startswith(b"HEAD ")
            ):
                continue
            
            request = dpkt.http.Request(data_bytes)

            findings = []

            if "?" in request.uri:
                query = request.uri.split("?", 1)[1]
                for part in query.split("&"):
                    if part == "":
                        continue
                    if "=" in part:
                        key, value = part.split("=", 1)
                    else:
                        key, value = part, ""
                    key = url_decode(key)
                    value = url_decode(value)
                    if len(value) > 4 and not value.isdigit():
                        findings.append(("Query", f"{key} = {value}"))

            if request.body:
                ctype = request.headers.get("content-type", "").lower()
                if "application/x-www-form-urlencoded" in ctype:
                    body_text = request.body.decode("utf-8", "ignore")
                    for part in body_text.split("&"):
                        if part == "":
                            continue
                        if "=" in part:
                            key, value = part.split("=", 1)
                        else:
                            key, value = part, ""
                        key = url_decode(key)
                        value = url_decode(value)
                        if len(value) > 4 and not value.isdigit():
                            findings.append(("Body", f"{key} = {value}"))
                else:
                    body_view = request.body.decode("utf-8", "ignore")
                    findings.append(("Body", body_view))

            for name, value in request.headers.items():
                if name.lower() not in COMMON and value:
                    findings.append(("Header", f"{name}: {value}"))

            if not findings:
                continue

            stamp = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            print("----- Interesting HTTP request -----")
            print(f"Timestamp : {stamp}")
            print(f"Client    : {src_ip}")
            print(f"Server    : {dst_ip}")
            print(f"Request   : {request.method} {request.uri}")

            for kind, detail in findings:
                print(f"{kind:7} {detail}")

            print()
