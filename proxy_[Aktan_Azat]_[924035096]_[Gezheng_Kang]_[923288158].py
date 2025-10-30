import socket
import json

HOST = "127.0.0.1"  
Proxy_PORT = 65111
IP_block_list = []   
error_msg = {"message": "Error"}


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
    # listen for client, aka, client -> proxy
    proxy.bind((HOST, Proxy_PORT))
    proxy.listen()
    client_socket, client_addr = proxy.accept()
    c_ip, c_port = client_addr
    # print(f"Proxy accepts connection from client on {c_ip}:{c_port}")

    with client_socket:
        dest_ip = None
        dest_port = None

        while True: 
            client_packet_raw = client_socket.recv(1024)

            if not client_packet_raw: break

            client_packet = json.loads(client_packet_raw.decode("utf-8"))
            dest_ip,dest_port, client_msg = client_packet["server_ip"], client_packet["server_port"], client_packet["message"]

            # already in blocklist
            if dest_ip is not None and (dest_ip, dest_port) in IP_block_list:
                # print("In the BLOCK_LIST. NO FORWARDING")
                client_socket.sendall(json.dumps(error_msg).encode("utf-8"))
                continue

            # not in blocklist
            if dest_ip is None or (dest_ip, dest_port) not in IP_block_list:
                    
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_socket.connect((dest_ip, dest_port))
                    # print(f"Proxy is connected server on {dest_ip}:{dest_port}")

                    to_server_client_msg = json.dumps({"message": client_msg}).encode("utf-8")
                    server_socket.sendall(to_server_client_msg)

                    server_response = server_socket.recv(1024)
                    client_socket.sendall(server_response)
                    
                    IP_block_list.append((dest_ip, dest_port))
                         





