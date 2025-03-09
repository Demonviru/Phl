import os

def create_directories_and_files(base_path):
    directories = [
        "app/src/main/java/com/example/payload",
        "app/src/main/res/layout",
        "app/src/main/res/values",
        "app/src/main/AndroidManifest.xml"
    ]

    files = [
        "app/src/main/java/com/example/payload/MainActivity.java",
        "app/src/main/java/com/example/payload/ClientService.java",
        "app/src/main/java/com/example/payload/CommandHandler.java",
        "app/src/main/java/com/example/payload/Utils.java",
        "app/src/main/res/layout/activity_main.xml",
        "app/src/main/res/values/strings.xml",
        "build.gradle",
        "settings.gradle"
    ]

    for directory in directories:
        path = os.path.join(base_path, directory)
        os.makedirs(path, exist_ok=True)
        print(f"Created directory: {path}")

    for file in files:
        path = os.path.join(base_path, file)
        with open(path, 'w') as f:
            pass
        print(f"Created file: {path}")

if __name__ == "__main__":
    base_path = "android_payload"
    create_directories_and_files(base_path)
