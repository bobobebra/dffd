#!/usr/bin/env python3
"""
win_server.py — Windows remote-control server (run on the Windows host)

Usage:
  python win_server.py --setup          # create config in %LOCALAPPDATA%\WinRC\config.json (interactive)
  python win_server.py --run            # run server (foreground)
  python win_server.py --kill           # send local shutdown to running server (localhost)

When built to an exe with PyInstaller using --noconsole, it will run silently.
"""
import os, sys, json, socket, threading, base64, hmac, hashlib, time, argparse, subprocess
from pathlib import Path
from io import BytesIO

APP_NAME = "WinRC"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "server.log"
KILL_FILE = APP_DIR / "kill.switch"
STOP_EVENT = threading.Event()

# ----------------- Try imports -----------------
# PyAutoGUI and Pillow are required. If running as an exe these are bundled.
try:
    import pyautogui
    from PIL import Image
except Exception as e:
    # helpful error for dev-time runs
    print("Missing dependency:", e)
    raise

# ----------------- helpers -----------------
def log(msg):
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass

def gen_secret():
    import secrets, base64
    return base64.b64encode(secrets.token_bytes(32)).decode()

def sign(secret_bytes: bytes, payload: bytes) -> str:
    return hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()

def verify(secret_bytes: bytes, payload: bytes, signature: str) -> bool:
    try:
        return hmac.compare_digest(sign(secret_bytes, payload), signature)
    except Exception:
        return False

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

# ----------------- config -----------------
DEFAULT = {
    "port": 50000,
    "shared_secret": "",   # filled at setup
    "allow": {
        "keys": True,
        "mouse": True,
        "screenshot": True,
        "shutdown": True
    }
}

def load_config():
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return None

def save_config(cfg):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

# ----------------- setup -----------------
def setup_interactive():
    cfg = DEFAULT.copy()
    cfg["shared_secret"] = gen_secret()
    print("=== WinRC setup ===")
    port = input(f"Port [default {cfg['port']}]: ").strip()
    if port.isdigit():
        cfg["port"] = int(port)
    print("Generated shared secret (copy this for your Linux controller):")
    print(cfg["shared_secret"])
    save_config(cfg)
    print("Config saved to:", CONFIG_PATH)

# ----------------- killfile watcher -----------------
def killfile_watchdog():
    while not STOP_EVENT.is_set():
        if KILL_FILE.exists():
            log("Kill file detected, stopping.")
            STOP_EVENT.set()
            break
        time.sleep(1.0)

# ----------------- client handler -----------------
def handle_client(conn, addr, cfg):
    secret = cfg["shared_secret"].encode()
    allow = cfg.get("allow", {})
    try:
        conn.settimeout(10)
        hello = recv_json(conn)
        if not hello or hello.get("type") != "auth":
            send_json(conn, {"type":"auth_resp","ok":False,"reason":"no auth"}); return
        payload = (hello.get("payload") or "").encode()
        if not verify(secret, payload, hello.get("sig","")):
            send_json(conn, {"type":"auth_resp","ok":False,"reason":"bad signature"}); return
        send_json(conn, {"type":"auth_resp","ok":True})
        conn.settimeout(None)

        while not STOP_EVENT.is_set():
            msg = recv_json(conn)
            if msg is None:
                break
            body = msg.get("body") or {}
            if not verify(secret, json.dumps(body).encode(), msg.get("sig","")):
                send_json(conn, {"type":"error","reason":"bad signature"}); continue
            act = body.get("action")
            if act == "keypress" and allow.get("keys", True):
                pyautogui.press(str(body.get("key")))
                send_json(conn, {"type":"ok"}); continue
            if act == "hotkey" and allow.get("keys", True):
                pyautogui.hotkey(*body.get("keys", [])); send_json(conn, {"type":"ok"}); continue
            if act == "click" and allow.get("mouse", True):
                pyautogui.click(); send_json(conn, {"type":"ok"}); continue
            if act == "move" and allow.get("mouse", True):
                x = int(body.get("x", 0)); y = int(body.get("y", 0))
                pyautogui.moveTo(x, y); send_json(conn, {"type":"ok"}); continue
            if act == "screenshot" and allow.get("screenshot", True):
                img = pyautogui.screenshot()
                buf = BytesIO(); img.save(buf, format="PNG")
                send_json(conn, {"type":"screenshot","data":base64.b64encode(buf.getvalue()).decode()}); continue
            if act == "shutdown" and allow.get("shutdown", True):
                send_json(conn, {"type":"ok","msg":"stopping"}); STOP_EVENT.set(); break
            send_json(conn, {"type":"error","reason":"unknown/disabled action"})
    except Exception as e:
        try: send_json(conn, {"type":"error","reason":str(e)})
        except: pass
    finally:
        conn.close()

# ----------------- server run -----------------
def run_server():
    cfg = load_config()
    if not cfg or not cfg.get("shared_secret"):
        print("Config missing: run --setup first"); return
    port = int(cfg.get("port", 50000))
    log(f"Starting on 0.0.0.0:{port}")
    t = threading.Thread(target=killfile_watchdog, daemon=True); t.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    s.settimeout(1.0)
    try:
        while not STOP_EVENT.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            log(f"Client connected: {addr}")
            threading.Thread(target=handle_client, args=(conn, addr, cfg), daemon=True).start()
    finally:
        s.close()
        log("Server stopped")

# ----------------- local kill -----------------
def local_kill():
    cfg = load_config()
    if not cfg:
        print("No config"); return
    port = cfg.get("port", 50000); secret = cfg["shared_secret"].encode()
    body = {"action":"shutdown"}
    msg = {"type":"action","body":body,"sig":sign(secret, json.dumps(body).encode())}
    hello_payload = b"local-kill"
    hello = {"type":"auth","payload":hello_payload.decode(),"sig":sign(secret, hello_payload)}
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
            send_json(c, hello); _ = recv_json(c); send_json(c, msg)
        print("Shutdown sent")
    except Exception as e:
        print("Send failed:", e)

# ----------------- main -----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--kill", action="store_true")
    args = parser.parse_args()
    if args.setup:
        setup_interactive()
    elif args.run:
        run_server()
    elif args.kill:
        local_kill()
    else:
        print("Use --setup / --run / --kill")
