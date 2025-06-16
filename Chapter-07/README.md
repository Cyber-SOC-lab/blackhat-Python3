# 🧠 Chapter 07 — GitHub-Based Trojan: Dynamic Remote Code Execution

This chapter demonstrates how to build a stealthy Python-based trojan that communicates with GitHub as a command-and-control (C2) server. It dynamically fetches Python modules to execute remote code and exfiltrate data back to the repository.

> **Warning**: These tools are intended for **authorized security testing and learning purposes only**. Do **not** use them against systems you do not own or have explicit permission to test. Misuse can lead to legal consequences.

---


## 📦 Components Overview

| Script/File              | Purpose                                                                            |
| ------------------------ | ---------------------------------------------------------------------------------- |
| `git_trojan.py`         | Main script that runs continuously, fetches modules, and reports results to GitHub |
| `modules/dirlister.py`   | Lists the files in the current directory                                           |
| `modules/environment.py` | Dumps current environment variables                                                |
| `modules/screenshot.py`  | Captures a screenshot and sends it back to GitHub                                  |
| `modules/keylogger.py`   | Starts a keylogger and captures typed keystrokes                                   |
| `abc.json`               | JSON configuration file fetched from GitHub to determine which modules to run      |



## 🔧 Prerequisites

Before using the trojan:

### 1. GitHub Setup
- A GitHub account.
- A private repository.
- A personal access token with full repo scope permissions.

Required folders in the repo:

### modules/ → store module scripts here
### data/abc/ → where exfiltrated results will be stored

### 2. Python Requirements (on victim machine)
- Python 3.6+
- Install required packages:

```bash
  pip install requests pyautogui pynput
```

## 🧪 Usage Guide
### 🔐 Step 1: Setup GitHub Repository
- Create a private GitHub repository (e.g., blackhat-trojan).
- Create the following directory structure:

```bash
  blackhat-trojan/
├── abc.json
├── modules/
│   ├── dirlister.py
│   ├── environment.py
│   ├── screenshot.py
│   └── keylogger.py
└── data/abc/
```
- Upload the abc.json file with the desired module list:

```json
    [
  { "module": "dirlister" },
  { "module": "environment" },
  { "module": "screenshot" },
  { "module": "keylogger" }
]
```

### 💻 Step 2: Configure & Run Trojan
Edit main_trojan.py and enter your GitHub credentials:

```bash
GITHUB_TOKEN = input("YOUR_GITHUB_TOKEN: ")
GITHUB_USERNAME = input("YOUR_USERNAME: ")
GITHUB_REPO = input("Enter your repository: ")
GITHUB_BRANCH = input("Enter your branch: ")
```

Then run:

```bash
  python main_trojan.py
```


---

## 🧠 How It Works
- Dynamic Importing: The trojan dynamically fetches **.py** files from **modules/** in your GitHub repo.

- Configuration-Based Execution: It reads **abc.json** to determine which modules to load and run.

- Threaded Execution: Each module runs in its own thread to simulate multitasking.

- Result Uploading: Outputs are encoded in base64 and uploaded back to **data/abc/***.data on GitHub.

- Stealth: Since GitHub is used as C2, it blends in with legitimate traffic.


## ⚙️ Features & Functionalities

| Feature              | Description                                                                    |
| -------------------- | ------------------------------------------------------------------------------ |
| Remote Configuration | `abc.json` fetched from GitHub defines which modules to run                    |
| Custom Module Loader | Uses `importlib` and `GitImporter` to dynamically load `.py` files from GitHub |
| Data Exfiltration    | Captured data is base64-encoded and pushed to GitHub as a `.data` file         |
| Modular Architecture | Easily expandable — just add new modules to the repo and update the JSON       |
| Screenshot Capture   | Captures screen using `pyautogui`                                              |
| Keylogger            | Logs keystrokes using `pynput` and saves to a file                             |


## ⚠️ Legal & Ethical Notice

This project is part of ethical cybersecurity research and education. You are fully responsible for how you use this code. Misuse may violate laws and regulations in your jurisdiction.

Do NOT:
- Run this code on systems you don’t own.
- Use it for unauthorized surveillance or exfiltration.

Use responsibly, with informed consent and proper legal authorization.

## 🧠 Final Notes

This chapter demonstrates how attackers can leverage legitimate infrastructure (like GitHub) for stealth and scalability. As defenders or red-teamers, understanding these techniques improves your ability to detect and counter such threats.

If you'd like help crafting more modules or building a monitoring system for detecting GitHub-based C2, feel free to ask!

