import socket
import time


HOST = "127.0.0.1"
PORT = 65336
DONE_MESSAGE = b"iperf-done"


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    server_socket.bind((HOST, PORT))
    print(f"Listening on {HOST}:{PORT}")

    total_bytes = 0
    start_time = None
    current_client = None

    while True:
        data, addr = server_socket.recvfrom(65535)

        if data == DONE_MESSAGE:
            if current_client != addr or total_bytes == 0 or start_time is None:
                server_socket.sendto(b"0.00", addr)
                continue

            elapsed = time.time() - start_time
            throughput = 0.0 if elapsed <= 0 else (total_bytes / 1024) / elapsed
            server_socket.sendto(f"{throughput:.2f}".encode(), addr)

            mb_received = total_bytes / (1024 * 1024)
            print(
                f"Received {mb_received:.2f} MB from {addr} in {elapsed:.3f} seconds "
                f"({throughput:.2f} KB/s)"
            )

            total_bytes = 0
            start_time = None
            current_client = None
            continue

        if current_client is None or current_client != addr:
            current_client = addr
            total_bytes = 0
            start_time = time.time()
            print(f"Receiving data from {addr}")

        total_bytes += len(data)
