import socket
from px import diffiehellman

def client(server_host='127.0.0.1', server_port=5000):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    print("Client 2: Connected to server. Starting key exchange...")

    # Perform Diffie-Hellman key exchange
    shared_key = diffiehellman(client_socket)
    print(f"Client 2: Shared key established: {shared_key.hex()}")

    client_socket.close()


if __name__ == "__main__":
    client()
