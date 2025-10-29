#!/usr/bin/env python3
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 5500

name = sys.argv[1]

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    print(f"{name} sending to {HOST}:{PORT}")
    while True:
        client.sendto(b"ping", (HOST, PORT))
        print(f"{name} sent ping")
        data, addr = client.recvfrom(1024)
        print(f"{name} received {data.decode()} from {addr}")
        time.sleep(1)
