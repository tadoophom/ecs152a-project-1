import socket
import json

HOST = "127.0.0.1"
Proxy_PORT = 65111
Server_PORT = 65333

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
    # listen for client, aka, client -> proxy
    proxy.bind((HOST,Proxy_PORT))
    proxy.listen()
    client_socket, client_addr = proxy.accept()
    c_ip, c_port = client_addr
    print(f"Proxy accepts connection from client on {c_ip}:{c_port}")

    # send to server, aka, proxy -> server
    with client_socket, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.connect((HOST, Server_PORT))
        print(f"Proxy is connected server on {HOST}:{Server_PORT}")
        while True: 
            data = client_socket.recv(1024)
            if not data: 
                break
            server.sendall(data)

            print("In proxy, the sent msg from client to server via proxy is: ", (json.loads(data.decode("utf-8")))["message"])
            server_response = server.recv(1024)
            client_socket.sendall(server_response)
            print("In cproxy, the received msg from server to client via proxy is: ", (json.loads(server_response.decode("utf-8")))["message"])
