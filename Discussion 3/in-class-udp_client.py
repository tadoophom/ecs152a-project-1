import socket
import time

SERVER_HOST = "127.0.0.1" #localhost
SERVER_PORT = 65333

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    while True:
        message = b"ping"
        client.sendto(message, (SERVER_HOST, SERVER_PORT))
        data, addr = client.recvfrom(1024)
        print(f"Data received: {data.decode}")
        print(f"Recevied from: {addr}")
        time.sleep(1)