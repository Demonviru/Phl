import os

# Define the folder structure
folders = [
    'app/src/main/java/com/example/client',
    'app/src/main/res/layout',
    'app/src/main/res/values',
    'app/src/main/AndroidManifest.xml',
    'app/build.gradle',
    'build.gradle'
]

# Define the files to be created
files = [
    'app/src/main/java/com/example/client/MainActivity.java',
    'app/src/main/java/com/example/client/CommandHandler.java',
    'app/src/main/java/com/example/client/ServerConnection.java',
    'app/src/main/res/layout/activity_main.xml',
    'app/src/main/res/values/strings.xml',
    'app/src/main/AndroidManifest.xml',
    'app/build.gradle',
    'build.gradle',
    'settings.gradle'
]

def create_folders_and_files():
    # Create folders
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        print(f"Created folder: {folder}")

    # Create files
    for file in files:
        with open(file, 'w') as f:
            pass
        print(f"Created file: {file}")

if __name__ == "__main__":
    create_folders_and_files()
    print("Folder structure and files created successfully.")
