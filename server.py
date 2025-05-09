import socket
import threading

clients = []
names = []

def broadcast(message):
    for client in clients:
        client.send(message)

def handle_client(client):
    while True:
        try:
            msg = client.recv(1024)
            broadcast(msg)
        except:
            idx = clients.index(client)
            clients.remove(client)
            name = names.pop(idx)
            broadcast(f"{name} has left the chat.".encode())
            break

def receive():
    server.listen()
    print("Server listening...")
    while True:
        client, addr = server.accept()
        print(f"Connected with {addr}")

        client.send("NAME".encode())
        name = client.recv(1024).decode()
        names.append(name)
        clients.append(client)

        print(f"Name: {name}")
        broadcast(f"{name} has joined the chat.".encode())
        client.send("Connected to server!".encode())

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

host = '127.0.0.1'
port = 55555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))

receive()
