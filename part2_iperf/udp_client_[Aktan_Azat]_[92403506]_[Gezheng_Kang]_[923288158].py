import socket
import time


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65336
TOTAL_MB = 100
CHUNK_KB = 8
DONE_MESSAGE = b"done"
RESPONSE_TIMEOUT = 5  # seconds


total_bytes = TOTAL_MB * 1024 * 1024
chunk_size = CHUNK_KB * 1024
payload = bytes(chunk_size)

print(f"Sending {TOTAL_MB} MB to {SERVER_HOST}:{SERVER_PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    bytes_sent = 0
    start_time = time.time()

    while bytes_sent < total_bytes:
        remaining = total_bytes - bytes_sent
        chunk = payload if remaining >= chunk_size else payload[:remaining]
        client_socket.sendto(chunk, (SERVER_HOST, SERVER_PORT))
        bytes_sent += len(chunk)

    client_socket.sendto(DONE_MESSAGE, (SERVER_HOST, SERVER_PORT))

    client_socket.settimeout(RESPONSE_TIMEOUT)
    try:
        server_response, _ = client_socket.recvfrom(1024)
        elapsed = time.time() - start_time
        print(f"Finished in {elapsed:.3f} seconds")
        print(f"Server throughput: {server_response.decode()} KB/s")
    except socket.timeout:
        print("Timed out waiting for server response")
