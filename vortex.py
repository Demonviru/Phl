import sys
import socket
import threading
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QInputDialog
)
from PySide6.QtCore import Qt

class ChatClient(QWidget):
    def __init__(self, host='127.0.0.1', port=55555):
        super().__init__()
        self.setWindowTitle("Chat Client")

        self.layout = QVBoxLayout()
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.message_input = QLineEdit()
        self.send_button = QPushButton("Send")

        self.layout.addWidget(self.chat_display)
        self.layout.addWidget(self.message_input)
        self.layout.addWidget(self.send_button)
        self.setLayout(self.layout)

        self.send_button.clicked.connect(self.send_message)
        self.message_input.returnPressed.connect(self.send_message)

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))

        self.username = QInputDialog.getText(self, "Enter Name", "Name:")[0]
        self.running = True

        self.receive_thread = threading.Thread(target=self.receive)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def send_message(self):
        msg = self.message_input.text()
        if msg:
            message = f"{self.username}: {msg}"
            self.client.send(message.encode())
            self.message_input.clear()

    def receive(self):
        while self.running:
            try:
                message = self.client.recv(1024).decode()
                if message == "NAME":
                    self.client.send(self.username.encode())
                else:
                    self.chat_display.append(message)
            except:
                self.chat_display.append("Connection lost.")
                self.client.close()
                break

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatClient()
    window.resize(400, 300)
    window.show()
    sys.exit(app.exec())
