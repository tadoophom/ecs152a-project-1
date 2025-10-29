import socket

HOST = "127.0.0.1" # every packet will remain on device
PORT = 65333

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind((HOST, PORT))
    while True:
        data, addr = server.recvfrom(1024)
        print(f"Data received: {data.decode}")
        print(f"Recevied from: {addr}")
        message = b"pong"
        server.sendto(message, addr)