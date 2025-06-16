import ctypes
import time
import random
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

keystrokes = 0
mouse_clicks = 0

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint),
                ("dwTime", ctypes.c_ulong)]

def get_last_input():
    struct_last_input = LASTINPUTINFO()
    struct_last_input.cbSize = ctypes.sizeof(LASTINPUTINFO)

    user32.GetLastInputInfo(ctypes.byref(struct_last_input))
    duration = kernel32.GetTickCount()
    elapsed = duration - struct_last_input.dwTime

    print(f"[*] It's been {elapsed} milliseconds since the last input event.")
    return elapsed

def get_key_press():
    global keystrokes
    global mouse_clicks

    for i in range(0, 0xff):
        if user32.GetAsyncKeyState(i) == -32767:  # key press detected
            if i == 0x01:  # left mouse click
                mouse_clicks += 1
                return time.time()
            elif 32 <= i <= 126:
                keystrokes += 1
                return time.time()
    return None

def sandbox_detection():
    global keystrokes, mouse_clicks

    max_keystrokes = random.randint(10, 25)
    max_mouse_clicks = random.randint(5, 25)
    max_double_clicks = 10
    double_clicks_threshold = 0.25  # seconds
    max_input_threshold = 3000  # milliseconds

    double_clicks = 0
    first_double_click = None
    previous_timestamp = None

    last_input = get_last_input()
    if last_input >= max_input_threshold:
        sys.exit(0)

    while True:
        keypress_time = get_key_press()

        if keypress_time is not None and previous_timestamp is not None:
            elapsed = keypress_time - previous_timestamp

            if elapsed <= double_clicks_threshold:
                double_clicks += 1
                if first_double_click is None:
                    first_double_click = time.time()
                elif double_clicks == max_double_clicks:
                    if keypress_time - first_double_click <= (max_double_clicks * double_clicks_threshold):
                        sys.exit(0)

        if (keystrokes >= max_keystrokes and
            mouse_clicks >= max_mouse_clicks and
            double_clicks >= max_double_clicks):
            return

        if keypress_time is not None:
            previous_timestamp = keypress_time

sandbox_detection()
print("We are ok!")








