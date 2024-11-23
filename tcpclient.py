#!/usr/bin/env python3

import socket

def tcp_client(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(message.encode())
            data = s.recv(1024)  # Receive up to 1024 bytes
            print(f"Received: {data.decode()}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    #host = "172.31.28.82"  # Replace with your server's hostname or IP
    host = "secondary.hyperkube.net"  # Replace with your server's hostname or IP
    #host = "127.0.0.1"  # Replace with your server's hostname or IP
    port = 5056  # Replace with your server's port
    message = "Hello, TCP Server!"
    tcp_client(host, port, message)

