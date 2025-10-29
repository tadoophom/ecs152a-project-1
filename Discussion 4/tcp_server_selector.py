import socket
import selectors

HOST = "127.0.0.1"
PORT = 65336

def handle_client(client_socket, client_host, client_port):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                print(f"Connection closed by {client_host}:{client_port}")
                break
            print(f"Message from {client_host}:{client_port} - {data.decode()}")
            message = b"pong!"
            try:
                client_socket.sendall(message)
            except (BrokenPipeError, ConnectionResetError):
                print(f"Client {client_host}:{client_port} disconnected (broken pipe)")
                break
    except Exception as e:
        print(f"Error with client {client_host}:{client_port}: {e}")

def accept(server_socket):
    client_socket, (client_host, client_port) = server_socket.accept()
    sel.register(client_socket, selectors.EVENT_READ, data=(client_host, client_port))

sel = selectors.DefaultSelector()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    server.setblocking(False)
    sel.register(server, selectors.EVENT_READ, data=None)
    while True:
        events = sel.select()
        for key, _ in events:
            if key.data is None:
                accept(key.fileobj)
            else:
                client_host, client_port = key.data
                handle_client(key.fileobj, client_host, client_port)