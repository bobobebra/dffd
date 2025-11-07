#!/usr/bin/env python3
"""
MyRemoteRC — consent-based remote control server + setup + autostart + kill switches.

Features
- Setup wizard (first run or `--setup`): port, feature toggles, autostart.
- Per-user config (Windows: %LOCALAPPDATA%\MyRemoteRC, Linux: ~/.local/share/MyRemoteRC).
- Visible autostart:
    * Windows: Startup folder .cmd
    * Linux: systemd --user service
- Actions (toggleable): keypress, hotkey, mouse move/click, screenshot, open_url, download_file.
- Auth: HMAC signature using shared_secret (randomly generated at setup).
- Kill switches:
    1) Remote signed "shutdown" action
    2) Local CLI:  `python myremoterc.py --kill`
    3) Panic file: create `kill.switch` in the app dir

Convert to EXE on Windows:
    pip install pyinstaller
    pyinstaller --onefile myremoterc.py

On Linux you can run as plain Python or bundle with PyInstaller too.
"""

import os, sys, json, base64, hmac, hashlib, socket, threading, time, subprocess, shutil, argparse, textwrap
from io import BytesIO

# ---------- Paths & OS helpers ----------
APP_NAME = "MyRemoteRC"

def is_windows():
    return os.name == "nt"

def app_dir():
    if is_windows():
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser(r"~\AppData\Local"))
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    return os.path.join(base, APP_NAME)

def config_path():
    return os.path.join(app_dir(), "config.json")

def log_path():
    return os.path.join(app_dir(), "server.log")

def startup_path_windows():
    return os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup", f"{APP_NAME}.cmd")

def systemd_unit_path():
    return os.path.join(os.path.expanduser("~/.config/systemd/user"), f"{APP_NAME}.service")

def exe_self_path():
    # When frozen (PyInstaller), sys.executable is the exe
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)

# ---------- Minimal logger ----------
def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg)
    print(line, flush=True)
    try:
        os.makedirs(app_dir(), exist_ok=True)
        with open(log_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ---------- Safe import with auto-install (only in .py mode) ----------
def ensure_deps():
    needed = ["PIL", "pyautogui"]
    missing = []
    try:
        import PIL  # noqa
    except Exception:
        missing.append("pillow")
    try:
        import pyautogui  # noqa
    except Exception:
        missing.append("pyautogui")

    if missing and not getattr(sys, "frozen", False):
        log(f"Missing deps: {missing}. Attempting pip install to user site...")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "--user"] + missing
            subprocess.check_call(cmd)
        except Exception as e:
            log(f"Dependency install failed: {e}")
            raise

ensure_deps()
from PIL import Image  # noqa
import pyautogui       # noqa

# ---------- Crypto ----------
def sign(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify(secret: bytes, payload: bytes, signature: str) -> bool:
    try:
        return hmac.compare_digest(sign(secret, payload), signature)
    except Exception:
        return False

# ---------- Networking helpers ----------
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

# ---------- Config handling ----------
DEFAULT_CONFIG = {
    "port": 50000,
    "shared_secret": "",  # filled during setup
    "allow": {
        "keys": True,
        "mouse": True,
        "screenshot": True,
        "open_url": False,
        "download_file": True,
        "run_cmd": False  # left off by default; you can enable in setup
    },
    "autostart": {
        "enabled": False,
        "method": ""  # "windows_startup" or "systemd_user"
    }
}

def generate_secret():
    try:
        import secrets
        return base64.b64encode(secrets.token_bytes(32)).decode()
    except Exception:
        return base64.b64encode(os.urandom(32)).decode()

def load_config():
    p = config_path()
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        c = json.load(f)
    return c

def save_config(cfg):
    os.makedirs(app_dir(), exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

# ---------- Setup wizard ----------
def prompt_bool(q, default=False):
    suf = " [Y/n]:" if default else " [y/N]:"
    ans = input(q + suf + " ").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes", "true", "1")

def setup_wizard():
    log("Starting setup wizard…")
    cfg = DEFAULT_CONFIG.copy()
    cfg["shared_secret"] = generate_secret()
    print("\n=== MyRemoteRC setup ===")
    print("This will configure a small remote-control server for *your* user account.")
    print("Actions are authenticated with a secret and feature-limited by your choices.\n")

    # Port
    port_str = input(f"Port to listen on [default {cfg['port']}]: ").strip()
    if port_str:
        try:
            p = int(port_str)
            if p < 1 or p > 65535:
                raise ValueError
            cfg["port"] = p
        except Exception:
            print("Invalid port, using default.")

    # Features
    print("\nEnable/disable features (you can change later in config.json):")
    for k in list(cfg["allow"].keys()):
        current = cfg["allow"][k]
        cfg["allow"][k] = prompt_bool(f"Allow {k}?", default=current)

    # Autostart
    enable_auto = prompt_bool("\nAdd visible autostart so it runs when *you* log in?", default=False)
    if enable_auto:
        if is_windows():
            cfg["autostart"]["enabled"] = True
            cfg["autostart"]["method"] = "windows_startup"
        else:
            cfg["autostart"]["enabled"] = True
            cfg["autostart"]["method"] = "systemd_user"

    save_config(cfg)
    print("\nConfig saved at:", config_path())
    print("Shared secret (copy into your client):\n", cfg["shared_secret"], "\n")

    if cfg["autostart"]["enabled"]:
        try:
            install_autostart(cfg)
            print("Autostart installed.")
        except Exception as e:
            print("Autostart setup failed:", e)

    if is_windows():
        print("\nIf Windows Firewall prompts, allow on your Private network. You can also add rules manually.")
    else:
        print("\nIf you use ufw/firewalld, open the chosen TCP port on your LAN if needed.")

# ---------- Autostart installers ----------
def install_autostart(cfg):
    os.makedirs(app_dir(), exist_ok=True)
    runner = exe_self_path()

    if cfg["autostart"]["method"] == "windows_startup" and is_windows():
        sp = startup_path_windows()
        content = f'@echo off\r\nREM Launch {APP_NAME}\r\nstart "" "{runner}" --run\r\n'
        with open(sp, "w", encoding="utf-8") as f:
            f.write(content)
        log(f"Windows Startup launcher created: {sp}")
        return sp

    if cfg["autostart"]["method"] == "systemd_user" and not is_windows():
        unit_dir = os.path.dirname(systemd_unit_path())
        os.makedirs(unit_dir, exist_ok=True)
        unit = textwrap.dedent(f"""
        [Unit]
        Description={APP_NAME} user service

        [Service]
        ExecStart={runner} --run
        Restart=on-failure
        WorkingDirectory={app_dir()}

        [Install]
        WantedBy=default.target
        """).strip()
        with open(systemd_unit_path(), "w", encoding="utf-8") as f:
            f.write(unit)
        # Enable and start (user)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "--user", "enable", "--now", f"{APP_NAME}.service"], check=False)
        log(f"systemd --user unit installed: {systemd_unit_path()}")
        return systemd_unit_path()

    raise RuntimeError("Unknown or unsupported autostart method.")

def uninstall_autostart():
    if is_windows():
        sp = startup_path_windows()
        if os.path.exists(sp):
            os.remove(sp)
            log("Removed Windows Startup launcher.")
    else:
        up = systemd_unit_path()
        if os.path.exists(up):
            subprocess.run(["systemctl", "--user", "disable", "--now", f"{APP_NAME}.service"], check=False)
            os.remove(up)
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
            log("Removed systemd --user unit.")

# ---------- Server core ----------
STOP_EVENT = threading.Event()

def handle_client(conn, addr, cfg):
    secret = cfg["shared_secret"].encode()
    allow = cfg["allow"]
    try:
        conn.settimeout(10)
        hello = recv_json(conn)
        if not hello or hello.get("type") != "auth":
            send_json(conn, {"type": "auth_resp", "ok": False, "reason": "no auth"})
            return
        payload = (hello.get("payload") or "").encode()
        if not verify(secret, payload, hello.get("sig", "")):
            send_json(conn, {"type": "auth_resp", "ok": False, "reason": "bad signature"})
            return
        send_json(conn, {"type": "auth_resp", "ok": True})
        conn.settimeout(None)

        while not STOP_EVENT.is_set():
            msg = recv_json(conn)
            if msg is None:
                break
            body = msg.get("body") or {}
            if not verify(secret, json.dumps(body).encode(), msg.get("sig", "")):
                send_json(conn, {"type": "error", "reason": "bad signature"})
                continue

            t = msg.get("type")
            if t != "action":
                send_json(conn, {"type": "error", "reason": "unknown type"})
                continue

            action = body.get("action")
            # ---- Kill switch (remote) ----
            if action == "shutdown":
                send_json(conn, {"type": "ok", "msg": "shutting down"})
                STOP_EVENT.set()
                break

            # ---- Keys / mouse ----
            if action == "keypress" and allow["keys"]:
                k = str(body.get("key"))
                pyautogui.press(k)
                send_json(conn, {"type": "ok"})
                continue
            if action == "hotkey" and allow["keys"]:
                keys = body.get("keys") or []
                pyautogui.hotkey(*keys)
                send_json(conn, {"type": "ok"})
                continue
            if action == "move" and allow["mouse"]:
                x = int(body.get("x", 0)); y = int(body.get("y", 0))
                pyautogui.moveTo(x, y)
                send_json(conn, {"type": "ok"})
                continue
            if action == "click" and allow["mouse"]:
                pyautogui.click()
                send_json(conn, {"type": "ok"})
                continue

            # ---- Extras ----
            if action == "screenshot" and allow["screenshot"]:
                img = pyautogui.screenshot()
                buf = BytesIO(); img.save(buf, format="PNG")
                b64 = base64.b64encode(buf.getvalue()).decode()
                send_json(conn, {"type": "screenshot", "data": b64})
                continue

            if action == "open_url" and allow["open_url"]:
                import webbrowser
                url = str(body.get("url", ""))
                if url:
                    webbrowser.open(url)
                    send_json(conn, {"type": "ok"})
                else:
                    send_json(conn, {"type": "error", "reason": "no url"})
                continue

            if action == "download_file" and allow["download_file"]:
                path = body.get("path") or ""
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    send_json(conn, {"type": "file", "name": os.path.basename(path), "data": b64})
                else:
                    send_json(conn, {"type": "error", "reason": "file not found"})
                continue

            # Disabled or unknown
            send_json(conn, {"type": "error", "reason": "action not allowed or unknown"})
    except Exception as e:
        try:
            send_json(conn, {"type": "error", "reason": str(e)})
        except Exception:
            pass
    finally:
        conn.close()

def kill_file_watchdog():
    # Kill switch #3: panic file
    kf = os.path.join(app_dir(), "kill.switch")
    while not STOP_EVENT.is_set():
        if os.path.exists(kf):
            log("Kill switch file detected; stopping.")
            STOP_EVENT.set()
            break
        time.sleep(1.0)

def run_server():
    cfg = load_config()
    if not cfg or not cfg.get("shared_secret"):
        print("Config missing. Run setup first:  python myremoterc.py --setup")
        sys.exit(1)

    port = int(cfg.get("port", 50000))
    log(f"Starting server on 0.0.0.0:{port}")
    t_watch = threading.Thread(target=kill_file_watchdog, daemon=True)
    t_watch.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(10)
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
        log("Server stopped.")

# ---------- Local CLI kill (Kill switch #2) ----------
def send_local_shutdown():
    cfg = load_config()
    if not cfg:
        print("No config found.")
        return
    secret = cfg["shared_secret"].encode()
    body = {"action": "shutdown"}
    msg = {"type": "action", "body": body, "sig": sign(secret, json.dumps(body).encode())}
    hello_payload = b"local-kill"
    hello = {"type": "auth", "payload": hello_payload.decode(), "sig": sign(secret, hello_payload)}

    try:
        with socket.create_connection(("127.0.0.1", int(cfg["port"])), timeout=2) as c:
            send_json(c, hello)
            _ = recv_json(c)  # auth_resp
            send_json(c, msg)
            print("Shutdown signal sent.")
    except Exception as e:
        print("Failed to send shutdown:", e)

# ---------- Uninstall ----------
def uninstall_everything():
    print("This will stop the server, remove autostart, and delete", app_dir())
    if not prompt_bool("Continue?", default=False):
        print("Cancelled."); return
    # Try local kill
    send_local_shutdown()
    time.sleep(0.5)
    # Remove autostart
    try:
        uninstall_autostart()
    except Exception as e:
        log(f"Autostart uninstall error: {e}")
    # Remove folder
    try:
        shutil.rmtree(app_dir(), ignore_errors=True)
        print("Removed app directory.")
    except Exception as e:
        print("Failed to remove app directory:", e)

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="MyRemoteRC — setup and server")
    parser.add_argument("--setup", action="store_true", help="Run setup wizard")
    parser.add_argument("--run", action="store_true", help="Run the server")
    parser.add_argument("--kill", action="store_true", help="Kill running server on localhost (kill switch)")
    parser.add_argument("--autostart", action="store_true", help="Install autostart based on current config")
    parser.add_argument("--uninstall", action="store_true", help="Stop and remove autostart + app folder")
    args = parser.parse_args()

    os.makedirs(app_dir(), exist_ok=True)

    if args.setup:
        setup_wizard(); return
    if args.autostart:
        cfg = load_config()
        if not cfg:
            print("No config; run --setup first."); return
        if not cfg["autostart"]["enabled"]:
            print("Autostart is disabled in config. Enable it via --setup."); return
        install_autostart(cfg); return
    if args.kill:
        send_local_shutdown(); return
    if args.uninstall:
        uninstall_everything(); return
    if args.run:
        run_server(); return

    # default: friendly help
    print(textwrap.dedent(f"""
    {APP_NAME}
    ---------
    First-time setup:
        python {os.path.basename(__file__)} --setup

    Run server (foreground):
        python {os.path.basename(__file__)} --run

    Kill switches:
        python {os.path.basename(__file__)} --kill
        (or create file: {os.path.join(app_dir(), 'kill.switch')})
        (or send remote signed "shutdown" action)

    Autostart:
        Enable in setup, then:
        python {os.path.basename(__file__)} --autostart

    Uninstall completely:
        python {os.path.basename(__file__)} --uninstall
    """).strip())

if __name__ == "__main__":
    main()
