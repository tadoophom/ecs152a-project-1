import socket
import json

Server_HOST = "127.0.0.1"
Server_PORT = 65333

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((Server_HOST, Server_PORT))
    server.listen()

    proxy_socket, proxy_addr = server.accept()

    with proxy_socket:
        while True:
            data = proxy_socket.recv(1024)
            if not data:
                break
            print("In server, the received msg from client via proxy is: ", json.loads(data.decode("utf-8")))
            response = {"message": "Pong"}
            proxy_socket.sendall(json.dumps(response).encode("utf-8"))
