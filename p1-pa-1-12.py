import dpkt
import datetime
import socket
import os
from collections import Counter
# In mDNS, every two packets form a pair — one query asking for a name and one response providing the answer
#    — so 14 packets shown in wireshark represent 7 query–response transactions.
# Therefore, here, in this homework, we only count the number of transactions of MDNS.

import dpkt

def detect_protocol(ip):
    l4 = ip.data

    if isinstance(l4, dpkt.tcp.TCP):
        sport, dport = l4.sport, l4.dport
        data = l4.data or b""

        if sport == 443 or dport == 443:
            if data and data[0] in (0x14, 0x15, 0x16, 0x17): 
                return "HTTPS"
        if sport in (80, 8080) or dport in (80, 8080):
            if data and data.startswith(b"GET") or data.startswith(b"POST") or data.startswith(b"HTTP"):
                return "HTTP"

        if sport == 22 or dport == 22:
            return "SSH"
        if sport == 21 or dport == 21:
            return "FTP"
        if sport == 25 or dport == 25:
            return "SMTP"
        return None


    if isinstance(l4, dpkt.udp.UDP):
        sport, dport = l4.sport, l4.dport
        data = l4.data or b""

        if sport == 53 or dport == 53:
            return "DNS"
        if sport == 5353 or dport == 5353:
            return "mDNS"
        if sport == 123 or dport == 123:
            return "NTP"
        if sport == 67 or dport == 68:
            return "DHCP"
        if sport == 137 or dport == 137:
            return "NBNS"

    return None



def main(): 

    pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap')]
    # pcap_files = ["/Users/gegekang/Desktop/ecs 152a/hw1/part-1-google-ping.pcap"]
    # pcap_files = ["/Users/gegekang/Desktop/ecs 152a/hw1/part-2-example-com.pcap"]
    for pcap_path in pcap_files: 
        protocol_counter = Counter()
        f = open(pcap_path,'rb')
        filename = os.path.basename(pcap_path)
        pcap = dpkt.pcap.Reader(f)

        for timestamp, data in pcap:
            ts = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
            eth = dpkt.ethernet.Ethernet(data)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            p = detect_protocol(ip)
            if p is None: 
                continue
            protocol_counter[p] += 1

        protocol_counter = sorted(protocol_counter.items(), key=lambda x: x[1])
    
        print(f"This is the statistic of {filename}")
        for p, cnt in protocol_counter:
            print(f"There is a protocol - {p}, with count of {cnt}")
        print("---------------------------------------------------------------")

if __name__ == "__main__":
    print("---------------------- HW1 Part1-Parta-Q1 ---------------------- ")
    main()

