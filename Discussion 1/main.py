import dpkt
from dpkt.ip import IP
from dpkt.utils import inet_to_str


def main() -> None:
    unique_ips: set[str] = set()

    with open('in-class.pcapng', 'rb') as fh:
        pcap = dpkt.pcapng.Reader(fh)

        for _, data in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(data)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue

            ip = eth.data
            if not isinstance(ip, IP):
                continue

            unique_ips.add(inet_to_str(ip.src))
            unique_ips.add(inet_to_str(ip.dst))

    for ip_addr in sorted(unique_ips):
        print(ip_addr)


if __name__ == '__main__':
    main()
