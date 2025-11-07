#!/usr/bin/env python3
"""
client_headless.py — headless Windows client for PYinDAEMON host

Usage (test):
    python client_headless.py --host 192.168.1.35 --port 50000 --secret "BASE64SECRET"

To build silent exe:
    pyinstaller --onefile --noconsole client_headless.py
"""
import socket, json, time, threading, hmac, hashlib, base64, sys, argparse
from pathlib import Path

# --------- Configurable defaults ----------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50000
# Commands file and log file are placed in the user profile for visibility
USER_DIR = Path.home() / ".pyina"
COMMANDS_FILE = USER_DIR / "commands.json"
LOG_FILE = USER_DIR / "client.log"
# -----------------------------------------

# ---------- helpers ----------
def log(msg):
    USER_DIR.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def sign(secret_bytes: bytes, payload: bytes) -> str:
    return hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()

def send_json(conn, obj):
    raw = json.dumps(obj).encode()
    conn.sendall(len(raw).to_bytes(4, "big") + raw)

def recv_json(conn):
    hdr = conn.recv(4)
    if not hdr or len(hdr) < 4:
        return None
    length = int.from_bytes(hdr, "big")
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    if not data:
        return None
    return json.loads(data.decode())

# ---------- Connection / Session ----------
class ClientSession:
    def __init__(self, host, port, secret_b64):
        self.host = host
        self.port = int(port)
        self.secret = secret_b64.encode() if isinstance(secret_b64, str) else secret_b64
        self.sock = None
        self.lock = threading.Lock()
        self.connected = False

    def connect_and_auth(self, timeout=5):
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
            # auth
            payload = b"client-headless"
            sig = sign(self.secret, payload)
            send_json(s, {"type": "auth", "payload": payload.decode(), "sig": sig})
            resp = recv_json(s)
            if resp and resp.get("type") == "auth_resp" and resp.get("ok"):
                with self.lock:
                    self.sock = s
                    self.connected = True
                log(f"Connected & authed to {self.host}:{self.port}")
                return True
            else:
                s.close()
                log(f"Auth failed: {resp}")
                return False
        except Exception as e:
            log(f"Connect error: {e}")
            return False

    def close(self):
        with self.lock:
            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            log("Socket closed")

    def safe_send_action(self, body):
        with self.lock:
            if not self.connected or not self.sock:
                return {"error": "not_connected"}
            try:
                sig = sign(self.secret, json.dumps(body).encode())
                send_json(self.sock, {"type": "action", "body": body, "sig": sig})
                resp = recv_json(self.sock)
                return resp
            except Exception as e:
                log(f"Send error: {e}")
                self.close()
                return {"error": str(e)}

# ---------- Command file watcher ----------
def read_and_consume_commands():
    """
    Commands file format: JSON array of action objects, e.g.:
    [
      {"action":"keypress","key":"a"},
      {"action":"click"},
      {"action":"screenshot"}
    ]
    After reading and sending, this function atomically clears the file.
    """
    try:
        if not COMMANDS_FILE.exists():
            return []
        text = COMMANDS_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return []
        data = json.loads(text)
        if not isinstance(data, list):
            log("Commands file malformed: top-level must be a JSON array")
            return []
        # Clear file atomically
        COMMANDS_FILE.write_text("[]", encoding="utf-8")
        return data
    except Exception as e:
        log(f"Error reading commands file: {e}")
        return []

# ---------- Main loop ----------
def run_loop(client: ClientSession, poll_interval=1.0):
    # reconnect/backoff variables
    backoff = 1.0
    max_backoff = 30.0

    while True:
        try:
            if not client.connected:
                ok = client.connect_and_auth()
                if not ok:
                    # backoff then retry
                    log(f"Reconnect failed, backing off {backoff}s")
                    time.sleep(backoff)
                    backoff = min(max_backoff, backoff * 1.8)
                    continue
                else:
                    backoff = 1.0

            # read commands file
            cmds = read_and_consume_commands()
            if cmds:
                log(f"Found {len(cmds)} command(s); sending to host")
                for c in cmds:
                    # sanitize: allow only dicts with action string
                    if not isinstance(c, dict):
                        log("Skipping invalid command (not an object)")
                        continue
                    action = c.get("action")
                    if not action:
                        log("Skipping command without action")
                        continue
                    resp = client.safe_send_action(c)
                    log(f"Sent action {action} -> resp: {resp}")
                    # small delay between commands
                    time.sleep(0.15)

            # heartbeat/ping (optional)
            # we don't expect unsolicited messages from host; just sleep and continue
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            log("Interrupted by user, exiting")
            client.close()
            break
        except Exception as e:
            log(f"Main loop exception: {e}")
            client.close()
            time.sleep(2.0)

# ---------- CLI and entry ----------
def main():
    p = argparse.ArgumentParser(description="Headless client for PYinDAEMON host")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--secret", required=True, help="Shared secret from host config.json")
    p.add_argument("--poll", type=float, default=1.0, help="Poll interval (seconds) for commands file")
    args = p.parse_args()

    USER_DIR.mkdir(parents=True, exist_ok=True)
    # ensure commands file exists (start empty)
    if not COMMANDS_FILE.exists():
        COMMANDS_FILE.write_text("[]", encoding="utf-8")

    client = ClientSession(args.host, args.port, args.secret)
    log(f"Starting headless client to {args.host}:{args.port}")
    run_loop(client, poll_interval=args.poll)

if __name__ == "__main__":
    main()
