import socket
import threading

def server(host='127.0.0.1', port=5222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(2)
    print(f"Server listening on {host}:{port}...")

    clients = []

    while len(clients) < 2:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        clients.append(conn)

    print("Both clients connected. Facilitating key exchange...")

    # Relay keys between two clients
    client1, client2 = clients
    threading.Thread(target=relay_keys, args=(client1, client2)).start()
    threading.Thread(target=relay_keys, args=(client2, client1)).start()


def relay_keys(sender, receiver):
    try:
        while True:
            data = sender.recv(1024)
            if not data:
                break
            receiver.send(data)
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        sender.close()
        receiver.close()
        print("Connection closed.")


if __name__ == "__main__":
    server()
