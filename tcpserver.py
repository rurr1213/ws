#!/usr/bin/env python3

import socket
import threading

def handle_client(conn, addr):
    print(f'Connected by {addr}')
    while True:
        data = conn.recv(1024)
        print(f'Recvd {data}')
        if not data: break
        conn.sendall(data)
        print(f'Sent {data} to {addr}')
    conn.close()

def tcp_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        while True:  # Accept multiple clients
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    #host = "secondary.hypercube.net127.0.0.1"  # Listen on localhost for testing
    host = "0.0.0.0" # Listen on all interfaces (if you want external access)
    port = 5056  # Choose a port not in use
    tcp_server(host, port)
