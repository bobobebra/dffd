#!/usr/bin/env python3
"""
win_server_installer.py

Portable installer for WinRC server:
- When run, shows a clear consent GUI describing what will happen.
- On consent it copies the running exe to %LOCALAPPDATA%\WinRC\win_server.exe
- Writes config.json (port + shared_secret)
- Registers a per-user Scheduled Task to run at logon (visible in Task Scheduler)
- Optionally adds a firewall rule (requires elevation; will try and warn)
- Leaves logs in %LOCALAPPDATA%\WinRC\

How to build:
  pip install pyinstaller
  pyinstaller --onefile --noconsole win_server_installer.py
The result (dist\win_server_installer.exe) is what you copy to target PCs.

IMPORTANT: Run this ONLY on machines you own/are authorized to manage. Installer is explicit and visible.
"""
import os, sys, json, time, shutil, subprocess
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, simpledialog

# ---------- Config ----------
APP_NAME = "WinRC"
INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
TARGET_EXE_NAME = "win_server.exe"   # the installed server name
CONFIG_NAME = "config.json"
LOG_NAME = "installer.log"

# Minimal server stub: The installer will copy itself (current exe) to target path.
# The actual server code can be the same file (installer) when called with --run,
# or you can replace the installed exe later with a different build. For simplicity
# we'll allow the installed exe to be the same binary and run with --run arg.

# ---------- Utilities ----------
def log(msg):
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        with open(INSTALL_DIR / LOG_NAME, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass

def gen_secret():
    import secrets, base64
    return base64.b64encode(secrets.token_bytes(32)).decode()

def run_subprocess(cmd, sudo=False):
    # helper for running commands; returns (rc, stdout+stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except Exception as e:
        return 1, str(e)

# ---------- Installer actions ----------
def write_config(port, secret):
    cfg = {"port": int(port), "shared_secret": secret, "allow": {"keys": True, "mouse": True, "screenshot": True, "shutdown": True}}
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    with open(INSTALL_DIR / CONFIG_NAME, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log(f"Written config: port={port}")

def copy_self_to_install():
    """Copy running exe/script to INSTALL_DIR/TARGET_EXE_NAME.
       If running as a script (not frozen), copy the script and rename to .exe is not meaningful.
       This installer is intended to be frozen into a single exe with PyInstaller.
    """
    src = Path(sys.executable) if getattr(sys, "frozen", False) else Path(__file__).resolve()
    dest = INSTALL_DIR / TARGET_EXE_NAME
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(str(src), str(dest))
        # ensure executable bit (for consistency)
        os.chmod(dest, 0o755)
        log(f"Copied {src} -> {dest}")
        return True, str(dest)
    except Exception as e:
        log(f"Copy failed: {e}")
        return False, str(e)

def create_schtask(exe_path):
    """Create a per-user scheduled task that runs the exe at logon.
       Uses schtasks.exe with /SC ONLOGON. This is visible in Task Scheduler.
    """
    task_name = f"{APP_NAME}-Server"
    # wrap in double quotes properly for schtasks
    cmd = ["schtasks", "/Create", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN", task_name, "/TR", f'"{exe_path}" --run', "/F"]
    rc, out = run_subprocess(cmd)
    if rc == 0:
        log("Scheduled task created.")
        return True, out
    else:
        log(f"Schtasks failed: {out}")
        return False, out

def add_firewall_rule(port):
    """Try to add a firewall rule for Private profile. This may require elevation.
       We'll attempt and report result; failure does not abort install.
    """
    name = f"{APP_NAME}-{port}"
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow", "protocol=TCP", f"localport={port}", "profile=private"]
    rc, out = run_subprocess(cmd)
    if rc == 0:
        log("Firewall rule added.")
        return True, out
    else:
        log(f"Firewall rule failed: {out}")
        return False, out

# ---------- GUI consent flow ----------
def run_installer_flow():
    root = tk.Tk()
    root.withdraw()

    info = (
        f"This installer will (with your consent):\n\n"
        f"• Install the WinRC server into:\n  {INSTALL_DIR}\\\n"
        f"• Create a visible Scheduled Task named '{APP_NAME}-Server' that runs at logon\n"
        f"• Write a config file with a generated shared secret (you must copy this to your controller)\n"
        f"• Optionally add a Windows Firewall rule for the chosen port (may require admin)\n\n"
        "Only continue if you own or have permission to modify this PC. All files and the task are visible and removable.\n\n"
        "Continue?"
    )
    if not messagebox.askokcancel("WinRC installer — consent", info):
        messagebox.showinfo("Cancelled", "Installer cancelled by user.")
        return

    # port prompt
    port = simpledialog.askstring("Port", "Port to listen on (default 50000):")
    if not port or not port.strip().isdigit():
        port = "50000"

    # secret prompt (user may paste one, or press Cancel to generate)
    secret = simpledialog.askstring("Shared secret", "Paste a shared secret to use (leave empty to auto-generate):")
    if not secret:
        secret = gen_secret()

    # copy the running exe into place
    ok, info_msg = copy_self_to_install()
    if not ok:
        messagebox.showerror("Copy failed", f"Failed to copy installer to install folder:\n{info_msg}\n\nInstall aborted.")
        return

    # write config
    try:
        write_config(port, secret)
    except Exception as e:
        messagebox.showerror("Config error", f"Failed to write config: {e}")
        return

    # create scheduled task
    exe_path = str(INSTALL_DIR / TARGET_EXE_NAME)
    ok_task, out_task = create_schtask(exe_path)
    if not ok_task:
        messagebox.showwarning("Scheduled task", f"Could not create scheduled task automatically.\n\nOutput:\n{out_task}\n\nYou can create a task manually or run the installer as admin.")
    else:
        messagebox.showinfo("Scheduled task", f"Scheduled task created (visible in Task Scheduler): {APP_NAME}-Server")

    # firewall
    if messagebox.askyesno("Firewall", "Attempt to add a Windows Firewall rule for the chosen port? (may require admin)"):
        ok_fw, out_fw = add_firewall_rule(port)
        if ok_fw:
            messagebox.showinfo("Firewall", "Firewall rule added (Private profile).")
        else:
            messagebox.showwarning("Firewall", f"Could not add firewall rule automatically.\n\nOutput:\n{out_fw}\n\nYou can add it manually.")

    # final message with secret
    messagebox.showinfo("Installed",
                        f"Installation complete.\n\nInstall folder: {INSTALL_DIR}\nConfig: {CONFIG_NAME}\n\nShared secret (copy this to your controller):\n\n{secret}\n\nRemember to keep this secret private.")
    log("Install complete.")
    root.destroy()

# ---------- If run as EXE with --run, behave as server launcher ----------
def run_installed_mode():
    """If the exe is called with --run, we launch the server logic (the same binary)
       with argument --run; expected to exist as installed exe. We try to exec it.
       If you want the installer exe to also contain the full server code, you'd
       include server behavior here. For safety we attempt to re-exec the installed exe.
    """
    installed = INSTALL_DIR / TARGET_EXE_NAME
    if installed.exists():
        # run it in background
        subprocess.Popen([str(installed), "--run"], shell=False)
        log("Launched installed exe with --run.")
    else:
        log("Installed exe not found; cannot run.")
    # exit installer process (if we were the installer)
    sys.exit(0)

# ---------- main ----------
def main():
    # If called with --run, act as server-runner (to keep behavior consistent when scheduled task runs installed exe)
    if "--run" in sys.argv:
        run_installed_mode()

    # normal installer UI
    run_installer_flow()

if __name__ == "__main__":
    main()
