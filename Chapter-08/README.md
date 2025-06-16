# 📁 Chapter 08 — Advanced Persistence, Surveillance, and Evasion Techniques

Welcome to Chapter 08, where we take a deeper dive into advanced offensive tactics. This chapter focuses on data surveillance, environment evasion, persistence mechanisms, and low-level shellcode execution — concepts commonly explored in red teaming, penetration testing, and malware analysis.

> **⚠️ Disclaimer**: All scripts provided in this chapter are for educational and ethical security research purposes only. Unauthorized use of these scripts to monitor, intercept, or execute code on systems without explicit consent is strictly prohibited and may be illegal under various cybersecurity laws.

---

## 📌 Chapter Objectives
- Understand and implement real-world keylogging and clipboard interception.

- Detect virtual environments and sandboxes to evade analysis.

- Perform screenshot surveillance using low-level screen capture techniques.

- Load and execute base64-encoded shellcode in memory with zero disk footprint.

## 🧠 Scripts Overview

| Script                | Description                                                                      |
| --------------------- | -------------------------------------------------------------------------------- |
| `keylogger.py`        | Logs keystrokes, clipboard pastes, and active windows in real-time.              |
| `sandbox_detector.py` | Detects virtual/sandboxed environments based on user interaction metrics.        |
| `screenshot.py`       | Captures screenshots and stores them with a timestamped filename.                |
| `shellcode_loader.py` | Fetches base64-encoded shellcode from a remote server and executes it in memory. |

---

## 🛠️ Requirements & Dependencies

Ensure you have the following Python packages installed:

```bash
  pip install pynput pyperclip mss urllib3
```

| Dependency  | Used For                                                          |
| ----------- | ----------------------------------------------------------------- |
| `pynput`    | Listening to keyboard events.                                     |
| `pyperclip` | Reading clipboard data.                                           |
| `mss`       | Cross-platform screenshot capturing.                              |
| `urllib3`   | Lightweight HTTP client used for shellcode fetching.              |
| `ctypes`    | For allocating memory and executing shellcode. (standard library) |

---


## 🧪 Scripts Usage:

### 📄 keylogger.py
#### 🔍 Features
- Tracks all keystrokes and logs them with timestamps.
- Detects and logs clipboard paste events (Ctrl+V).
- Logs the currently active window on each change.

#### ▶️ How to Run

```bash
  python keylogger.py
```

Press ESC to stop logging.

🗂️ Output
All logs are written to keylog.txt.


### 📄 sandbox_detector.py
#### 🔍 Features
- Monitors keyboard and mouse interactions.
- Detects if interaction patterns are artificial (typical in sandboxes).
- Exits early if thresholds are not met (anti-analysis).

#### ▶️ How to Run

```bash
  python sandbox_detector.py

```

If enough user interaction is detected:
"We are ok!" is printed.

Otherwise, the script will silently terminate.


### 📄 screenshot.py
#### 🔍 Features
- Captures a full-screen screenshot.
- Automatically names screenshots with the current timestamp.

#### ▶️ How to Run

```bash
  python screenshot.py
```

🗂️ Output
Example output:

```bash
  screenshot_2025-06-13_12-35-45.png

```


### 📄 shell_exec.py

⚠️ Dangerous Script – Use with Caution

This script downloads base64-encoded shellcode and executes it in memory using ctypes.

#### 🔍 Features
- No file is written to disk — executes shellcode directly.
- Supports any custom shellcode payload.

#### ▶️ How to Run
Start a simple HTTP server where your shellcode file is hosted:

```bash

  python -m http.server 8000

```

Make sure shellcode.bin is in the same directory and base64-encoded.

Then run:

```bash
  python shellcode_loader.py
```

---


## 🚨 Legal & Ethical Usage Disclaimer

> The code and techniques in this chapter are for educational purposes only. Please don't deploy or execute these tools on devices you do not own or do not have explicit authorization to test. Misuse of these scripts can lead to criminal liability and serious consequences.

We strongly encourage responsible disclosure, ethical red teaming, and legal penetration testing practices.


## ✅ Summary

Chapter 08 encapsulates advanced real-world tactics for system interaction, sandbox evasion, and covert data collection. The code here is intentionally modular and practical — offering both research value and awareness about post-exploitation techniques in cybersecurity.
