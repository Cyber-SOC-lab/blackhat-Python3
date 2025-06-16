from mss import mss, tools
from datetime import datetime
import os

def take_snapshot(output_dir="."):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(output_dir, f"screenshot_{timestamp}.png")

    with mss() as sct:
        monitor = sct.monitors[1]  # Can be adjusted to sct.monitors[0] for all screens
        screenshot = sct.grab(monitor)
        tools.to_png(screenshot.rgb, screenshot.size, output=filename)
        print(f"[+] Screenshot saved to {filename}")

if __name__ == "__main__":
    take_snapshot()
