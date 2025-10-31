import socket
import json

Proxy_HOST = "127.0.0.1"
Proxy_PORT = 65111
Server_HOST = "127.0.0.1"
Server_PORT = 65333

json_data = {
    "server_ip": Server_HOST,     
    "server_port": Server_PORT,  
    "message": "Ping"          
}
payload = json.dumps(json_data).encode("utf-8")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((Proxy_HOST, Proxy_PORT))
    # print(f"Client is connected Proxy on {Proxy_HOST}:{Proxy_PORT}")

    i = 3
    # while True:
    while i > 0: 
        client.sendall(payload)
        server_response = client.recv(1024)
        data = json.loads(server_response.decode("utf-8"))
        print("In client, the received msg from server via proxy is: ", data["message"])
        i -= 1
