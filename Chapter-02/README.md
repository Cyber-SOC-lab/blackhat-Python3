# 🛠️ Chapter 2 – Building Network Tools in Python

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Paramiko](https://img.shields.io/badge/SSH-Paramiko-yellow.svg)](https://www.paramiko.org/)
![Status](https://img.shields.io/badge/status-Complete-brightgreen)

> 📖 From **Black Hat Python** – Learn how to craft powerful and stealthy networking tools using Python.

---

## 📚 Table of Contents

- [📁 Scripts Overview](#-scripts-overview)
- [🧰 Setup & Requirements](#-setup--requirements)
- [🔍 Detailed Script Descriptions](#-detailed-script-descriptions)
- [🔄 Inter-Script Relationships](#-inter-script-relationships)
- [📦 Libraries & Enhancements](#-libraries--enhancements)
- [📘 Conclusion](#-conclusion)

---

## 📁 Scripts Overview

| 🔢 | Script | Filename | Description |
|----|--------|----------|-------------|
| 1️⃣ | TCP Scanner | `scanner.py` | Port scanner with service banner grabbing |
| 2️⃣ | Net Module | `bhnet.py` | TCP socket engine with client/server logic |
| 3️⃣ | Netcat Clone | `netcat_clone.py` | Netcat alternative using `bhnet.py` |
| 4️⃣ | SSH Command Tool | `bh_sshRcmd.py` | Run remote commands via SSH |
| 5️⃣ | TCP Proxy | `proxy.py` | Intercept & manipulate traffic |
| 6️⃣ | Reverse SSH Tunnel | `reverse_ssh_tunnel.py` | Create SSH reverse tunnels |
| 7️⃣ | TCP Client | `tcp_client.py` | Interactive HTTP/TCP client |
| 8️⃣ | TCP Server | `tcp_server.py` | Multithreaded TCP server |
| 9️⃣ | UDP Client | `udp_client.py` | Interactive UDP messaging tool |

---

## 🧰 Setup & Requirements

✅ **Python Version**: Python 3.7 or higher  
📦 **Install Dependencies**:

```bash
pip install paramiko
```

#### 🔍 Detailed Script Descriptions

#### 1️⃣ scanner.py — 🔎 TCP Port Scanner
- Scans ports on a given host.
- Attempts to grab service banners.
- Built-in timeout and error handling.

#### 🚀 Usage:
```bash
python scanner.py 192.168.0.1
```

### 2️⃣. bhnet.py

### Functionality:
- Core network module for TCP communication.
- Used by other tools like netcat_replacement.py.

### Features:
- Listener mode with multi-threaded client handling.
- Client mode with stdin/stdout interaction.
- File upload and command execution support.

### Notable Improvements:
- Modular code separation.
- Graceful error handling.
- More secure threading and resource management.

#### 🚀 Usage:
```bash
python bhnet.py
```

#### 3️⃣ netcat_clone.py — 🧪 Netcat Clone
- Netcat-like tool built using bhnet.py engine.
- Offers features like listening on a port, connecting to remote hosts, and transferring data.
- Can upload files, execute commands remotely, and handle multiple connections.

Options:
- -l: Listen mode.
- -e: Execute a command.
- -c: Command shell.
- -u: Upload a file.

#### 🚀 Usage:
```bash
python netcat_clone.py -t 127.0.0.1 -p 9999 -l -c
```

#### 4️⃣ bh_sshRcmd.py — 🔐 SSH Command Execution
- Connects to a remote server via SSH.
- Executes a command and shows output.
- Uses paramiko for SSH sessions.

  #### 🚀 Usage:
```bash
  python bh_sshRcmd.py
```

#### 5️⃣ proxy.py — 🕵️ TCP Proxy for Traffic Analysis
- Intercepts TCP data between client and server.
- Hexdumps requests/responses for inspection.
- Modify data in real-time via hook functions.

  #### 🚀 Usage:
```bash
  python proxy.py 127.0.0.1 9000 example.com 80 True
```

### 6️⃣ reverse_ssh_tunnel.py — 🔁 Reverse SSH Tunnel
- Tunnel remote ports to local services.
- Similar to ssh -R in OpenSSH.
- Accepts passwords, key files, and command-line options.

  #### 🚀 Usage:
```bash
  python reverse_ssh_tunnel.py
```

#### 7️⃣ simple_tcp_client.py — 📡 Interactive TCP Client
- Sends HTTP requests interactively.
- Receives full server response.
- Graceful handling of errors and malformed hosts.

  #### 🚀 Usage:
```bash
  python simple_tcp_client.py
```

#### 8️⃣ tcp_server.py — 🖧 Threaded TCP Server
- Accepts client connections.
- Logs request content and replies with ACK.
- Uses threading for concurrent clients.

  #### 🚀 Usage:
```bash
  python tcp_server.py
```

#### 9️⃣ udp_client.py — 📬 UDP Client
- Sends a single UDP message.
- Receives a response if the server replies.
- Timeout handling for unresponsive targets.

  #### 🚀 Usage:
```bash
  python simple_udp_client.py
```

#### 🔄 Inter-Script Relationships
🔗 netcat_clone.py → uses bhnet.py as its engine
🔐 bh_sshRcmd.py & reverse_ssh_tunnel.py → use Paramiko for secure SSH communication
📡 proxy.py → can be tested with tcp_client.py and external services
🧪 udp_client.py → test against custom UDP server (optional)


#### 🔧 Common Enhancements
- ✅ Error handling and validation
- 🔄 Multithreading for concurrent connections
- 🧼 Clean, user-driven input instead of hardcoded values
- ♻️ Modular code for reusability
- 🪪 Secure credential input and file handling
- 🧵 Daemonized threads for background execution
- 🧱 Graceful shutdowns and keyboard interrupt handling


#### 📘 Conclusion
These tools showcase how Python can be used to build practical and powerful network utilities. They are:
- 🚀 Easy to extend
- 🔒 Useful for penetration testing
- 🧰 Educational for learning sockets, SSH, proxies, and more

Feel free to customize or contribute additional features as you grow your network engineering skills.
