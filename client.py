import socket, json, hmac, hashlib, base64
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QVBoxLayout, QHBoxLayout
import sys

# ---- HMAC helpers ----
def sign(secret: bytes, data: bytes):
    return hmac.new(secret, data, hashlib.sha256).hexdigest()

def send_json(sock, obj):
    raw = json.dumps(obj).encode()
    sock.sendall(len(raw).to_bytes(4, "big") + raw)

def recv_json(sock):
    hdr = sock.recv(4)
    if not hdr or len(hdr) < 4:
        return None
    length = int.from_bytes(hdr, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    if not data:
        return None
    return json.loads(data.decode())

# ---- GUI ----
class RemoteClient(QWidget):
    def __init__(self):
        super().__init__()
        self.sock = None
        self.secret = b""
        self.setWindowTitle("PYinDAEMON Controller")
        self.resize(480, 400)
        self.init_ui()

    def init_ui(self):
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Host IP (e.g. 192.168.1.35)")
        self.port_input = QLineEdit("50000")
        self.secret_input = QLineEdit()
        self.secret_input.setPlaceholderText("Shared secret from host config.json")
        self.secret_input.setEchoMode(QLineEdit.Password)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_host)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key to press (e.g. w, space)")
        self.key_btn = QPushButton("Send Key")
        self.key_btn.clicked.connect(self.send_key)

        self.click_btn = QPushButton("Mouse Click")
        self.click_btn.clicked.connect(self.send_click)

        self.ss_btn = QPushButton("Screenshot")
        self.ss_btn.clicked.connect(self.get_screenshot)

        self.shutdown_btn = QPushButton("Shutdown Host")
        self.shutdown_btn.clicked.connect(self.shutdown_host)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Host Connection"))
        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_input)
        layout.addWidget(self.secret_input)
        layout.addWidget(self.connect_btn)
        layout.addWidget(QLabel("Controls"))
        hl = QHBoxLayout()
        hl.addWidget(self.key_input)
        hl.addWidget(self.key_btn)
        layout.addLayout(hl)
        layout.addWidget(self.click_btn)
        layout.addWidget(self.ss_btn)
        layout.addWidget(self.shutdown_btn)
        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)
        self.setLayout(layout)

    # ---- Networking ----
    def connect_host(self):
        ip = self.ip_input.text().strip()
        port = int(self.port_input.text().strip())
        self.secret = self.secret_input.text().encode()
        try:
            self.sock = socket.create_connection((ip, port), timeout=5)
            payload = b"controller"
            sig = sign(self.secret, payload)
            send_json(self.sock, {"type": "auth", "payload": payload.decode(), "sig": sig})
            resp = recv_json(self.sock)
            if resp and resp.get("ok"):
                self.log.append("✅ Connected & authenticated.")
            else:
                self.log.append("❌ Auth failed.")
                self.sock = None
        except Exception as e:
            self.log.append(f"Connection error: {e}")
            self.sock = None

    def send_action(self, body):
        if not self.sock:
            self.log.append("Not connected.")
            return
        sig = sign(self.secret, json.dumps(body).encode())
        send_json(self.sock, {"type": "action", "body": body, "sig": sig})
        resp = recv_json(self.sock)
        if resp:
            self.log.append(str(resp))
        else:
            self.log.append("No response / connection lost.")

    def send_key(self):
        key = self.key_input.text().strip()
        if key:
            self.send_action({"action": "keypress", "key": key})

    def send_click(self):
        self.send_action({"action": "click"})

    def get_screenshot(self):
        self.send_action({"action": "screenshot"})
        resp = recv_json(self.sock)
        if resp and resp.get("type") == "screenshot":
            data = base64.b64decode(resp["data"])
            with open("screenshot_from_host.png", "wb") as f:
                f.write(data)
            self.log.append("🖼 Screenshot saved as screenshot_from_host.png")
        else:
            self.log.append("Failed to get screenshot.")

    def shutdown_host(self):
        self.send_action({"action": "shutdown"})
        self.log.append("🔴 Sent shutdown command to host.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = RemoteClient()
    w.show()
    sys.exit(app.exec_())
