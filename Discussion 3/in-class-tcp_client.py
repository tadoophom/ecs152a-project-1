import socket

SERVER_HOST = "127.0.0.1" #localhost
SERVER_PORT = 65334

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    message = b"Hello there!"
    client.connect((SERVER_HOST, SERVER_PORT))
    client.sendall(message)
    data = client.recv(1024)
    print(f"Data received: {data.decode}")
