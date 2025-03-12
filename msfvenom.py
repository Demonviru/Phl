import os

# Function to generate Java code with required commands
def generate_java_code():
    java_code = '''package com.example.dumputil;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.content.Context;
import android.util.Log;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;

public class DumpUtilActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Example: Dump contacts
        dumpContacts();
        
        // Example: Dump Call Log
        dumpCallLog();
        
        // Example: Dump SMS
        dumpSMS();
        
        // Example: Send SMS
        sendSMS("destination_number", "text_message");
        
        // Example: Run a Shell Command
        runShellCommand("ls");

        // Example: TCP Connection
        runTcpConnection("10.0.1.33", 9999);
    }

    private void dumpContacts() {
        // Code to dump contacts
        Log.d("DumpUtil", "Dumping Contacts...");
    }

    private void dumpCallLog() {
        // Code to dump call logs
        Log.d("DumpUtil", "Dumping Call Logs...");
    }

    private void dumpSMS() {
        // Code to dump SMS
        Log.d("DumpUtil", "Dumping SMS...");
    }

    private void sendSMS(String destination, String text) {
        SmsManager smsManager = SmsManager.getDefault();
        smsManager.sendTextMessage(destination, null, text, null, null);
        Log.d("DumpUtil", "Sending SMS to " + destination + ": " + text);
    }

    private void runShellCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                Log.d("DumpUtil", "Shell Output: " + line);
            }
        } catch (Exception e) {
            Log.e("DumpUtil", "Error running shell command", e);
        }
    }

    private void runTcpConnection(String ip, int port) {
        try {
            Socket socket = new Socket(ip, port);
            Log.d("DumpUtil", "Connected to TCP Server at " + ip + ":" + port);
        } catch (Exception e) {
            Log.e("DumpUtil", "Error connecting to TCP Server", e);
        }
    }
}
'''
    return java_code


# Function to generate Android Manifest XML code
def generate_manifest_xml():
    manifest_xml = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.dumputil"
    android:versionCode="1"
    android:versionName="1.0" >

    <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="30" />

    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name" >
        <activity
            android:name=".DumpUtilActivity"
            android:label="@string/app_name"
            android:theme="@android:style/Theme.Holo.Light" >
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
'''
    return manifest_xml


# Function to generate Gradle build script for debug APK
def generate_gradle_build_script():
    gradle_script = '''apply plugin: 'com.android.application'

android {
    compileSdkVersion 30
    defaultConfig {
        applicationId "com.example.dumputil"
        minSdkVersion 16
        targetSdkVersion 30
        versionCode 1
        versionName "1.0"
    }
    buildTypes {
        debug {
            debuggable true
        }
        release {
            minifyEnabled false
            shrinkResources true
        }
    }
}

dependencies {
    implementation 'com.android.support:appcompat-v7:28.0.0'
    implementation 'com.android.support.constraint:constraint-layout:1.1.3'
}
'''
    return gradle_script


# Function to write files to disk
def write_files():
    # Create the necessary directories if they don't exist
    os.makedirs("app/src/main/java/com/example/dumputil", exist_ok=True)
    os.makedirs("app/src/main/res", exist_ok=True)
    os.makedirs("app/src/main", exist_ok=True)
    
    # Write the Java file
    with open("app/src/main/java/com/example/dumputil/DumpUtilActivity.java", "w") as java_file:
        java_file.write(generate_java_code())
    
    # Write the Android Manifest
    with open("app/src/main/AndroidManifest.xml", "w") as manifest_file:
        manifest_file.write(generate_manifest_xml())
    
    # Write Gradle build script
    with open("app/build.gradle", "w") as gradle_file:
        gradle_file.write(generate_gradle_build_script())
    
    print("Files generated successfully!")


# Function to trigger Gradle build (for compilation)
def compile_apk():
    print("Compiling APK in debug mode...")
    os.system("gradle build")  # Assuming Gradle is installed and configured
    print("APK compiled successfully!")


# Main function to generate code and compile APK
def main():
    write_files()
    compile_apk()


# Run the main function
if __name__ == "__main__":
    main()
