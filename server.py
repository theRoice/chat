import socket

from threading import Thread

# initial python server code taken from: https://www.thepythoncode.com/article/make-a-chat-room-application-in-python

# SETUP
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002
separator_token = "<SEP>"

# Initialization
client_sockets = set()

server_socket = socket.socket()
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)

print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

def relay_from_client(source_client_socket: socket.socket):
    while True:
        try:
            incoming_bytes = source_client_socket.recv(4096)
            if not incoming_bytes:
                raise ConnectionError("Client disconnected")
        except Exception as error:
            print(f"[!] Client error/disconnect: {error}")
            if source_client_socket in client_sockets:
                client_sockets.remove(source_client_socket)
            try:
                source_client_socket.close()
            except Exception:
                pass
            break    
        
        for destination_client_socket in list(client_sockets):
            if destination_client_socket is source_client_socket:
                continue
            try:
                destination_client_socket.sendall(incoming_bytes)
            except Exception:
                try:
                    destination_client_socket.close()
                except Exception:
                    pass
                if destination_client_socket in client_sockets:
                    client_sockets.remove(destination_client_socket)

while True:
    client_socket, client_address = server_socket.accept()

    print(f"[+] {client_address} connected.")
    client_sockets.add(client_socket)
    
    client_thread = Thread(target=relay_from_client, args=(client_socket,), daemon=True)

    client_thread.start()