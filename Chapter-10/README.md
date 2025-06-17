# Chapter 10: Monitoring and Data Exfiltration

This chapter explores how adversaries can monitor system activities and exfiltrate data using Python and Windows-native features. The scripts demonstrate low-level process monitoring, file system surveillance, and stealthy background execution via Windows services.

> **Warning:** These scripts are for educational purposes only. Do not deploy or execute them on unauthorized systems.

---

## 📁 Contents

1. `process_mon.py`
   Monitors newly created processes and logs detailed information, including the process owner's privileges.

2. `File_mon.py`
   Continuously monitors sensitive temporary directories for file creation, modification, deletion, or renaming. Can inject payloads into specific file types.

3. `bhservice.zip`
   Creates a persistent Windows service that periodically runs a VBS script to gather system information.

---

## ⚙️ Requirements

* Python 3.x
* Windows OS
* Administrator privileges

### Python Libraries

Install the following Python packages:

```bash
pip install pywin32 wmi
```

---

## 🧪 Script Descriptions

### 1. `process_mon.py`

Logs information every time a process is created:

* Timestamp
* Executable path
* Command-line arguments
* User who initiated it
* Parent process ID
* Enabled privileges (e.g., SeDebugPrivilege)

📄 **Output:** Logged to `process_monitor_log_file.csv`

---

### 2. `File_mon.py`

Monitors temporary directories (`C:\WINDOWS\Temp`, system temp dir) for file system changes:

* Logs file creation, deletion, modification, or rename events
* On modification, attempts to inject payloads into `.vbs`, `.bat`, or `.ps1` files

🔐 **Payload Injection:**

```bash
.vbs → Executes bhpnet.exe via WScript
.bat → Inserts direct command to launch bhpnet
.ps1 → Uses PowerShell's Start-Process
```

---

### 3. `bhservice.zip`

Implements a Windows service (`BlackHatService`) that runs a VBS script every 60 seconds:

* VBS script (from `VBS.txt`) collects system, OS, BIOS, and memory information
* Writes output to `C:\windows\temp\bhpoutput.txt`

🛠 **Deployment Steps:**

1. Place `bhservice.py` and `VBS.txt` in a folder
2. Copy to target system
3. From elevated prompt:

```bash
python bhservice.py install
python bhservice.py start
```

📌 **Note:** Uses `cscript.exe` to execute VBS in background

---

## 🚧 Ethical Disclaimer

These scripts demonstrate powerful post-exploitation techniques. Misuse can lead to severe legal consequences. Use them only in safe, legal, and educational environments (e.g., labs, CTFs).

---

## 📚 Summary

Chapter 10 highlights how attackers can:

* Observe process execution in real-time
* Exploit file monitoring for payload injection
* Maintain persistence using system services

Understanding these techniques enables defenders to detect and mitigate advanced threats.

> Proceed responsibly and always with explicit authorization.
