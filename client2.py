import socket
from px import diffiehellman

# Constants
HOST = '127.0.0.1'  # Server address
PORT = 65432        # Server port


def main(name):
    """
    Client that connects to the server and performs a Diffie-Hellman key exchange.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"{name} connected to the server")

        # Perform Diffie-Hellman key exchange
        shared_key = diffiehellman(client_socket)
        print(f"{name}'s shared key: {shared_key.hex()}")


if __name__ == "__main__":
    # Change the name to "Alice" or "Bob" when running the script
    main("Client")
