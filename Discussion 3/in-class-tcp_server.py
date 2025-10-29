import socket

HOST = "127.0.0.1" # every packet will remain on device
PORT = 65334

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen() #indicates server is ready for incoming connections
    client_socket, (client_host, client_port) = server.accept()
    data = client_socket.recv(1024)
    print(f"Data received: {data.decode}")
    message = b"Hi there!"
    client_socket.sendto(message, (HOST, PORT))