import socket
import threading

# Constants
HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port to listen on


def relay_messages(client_1, client_2):
    """
    Relay messages between two clients.
    """
    try:
        # Relay messages between the two clients
        while True:
            # Receive data from Client 1 and send to Client 2
            data = client_1.recv(1024)
            if not data:
                break
            client_2.send(data)

            # Receive data from Client 2 and send to Client 1
            data = client_2.recv(1024)
            if not data:
                break
            client_1.send(data)
    except Exception as e:
        print(f"Error relaying messages: {e}")
    finally:
        client_1.close()
        client_2.close()


def main():
    """
    Main server to relay messages between two clients.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(2)
        print("Server is listening for two clients...")

        # Accept two client connections
        client_1, addr_1 = server_socket.accept()
        print(f"Client 1 connected from {addr_1}")
        client_2, addr_2 = server_socket.accept()
        print(f"Client 2 connected from {addr_2}")

        # Start relaying messages between the two clients
        relay_messages(client_1, client_2)


if __name__ == "__main__":
    main()
