# 📘 Chapter 5: Web Recon & Bruteforcing — README

Welcome to **Chapter 5** of our Python Networking & Hacking Series! 🌐🔐  
This chapter focuses on **web-based reconnaissance**, **directory bruteforcing**, and **credential attacks** using multithreaded HTTP requests and HTML parsing. It gives you powerful insight into how attackers discover vulnerabilities and how you can test your own web assets defensively.

---

## 🧰 Prerequisites


## ⚠️ Legal Disclaimer

> ⚠️ **USE RESPONSIBLY — FOR EDUCATIONAL PURPOSES ONLY!**  
> These scripts are designed to **demonstrate real-world security flaws** and are to be run **only on networks you own or have permission to test**.  
> Unauthorized use of these tools is **illegal and unethical**.

> ⚠️ **Admin/root privileges not strictly required**, but some endpoints might need server-side permissions.

* Python 3.6+
* Basic understanding of HTTP/Web App logic
* Run in environments where permission is granted to test endpoints

### 📦 Libraries Used

- urllib3
- threading
- queue
- os
- html.parser
- http.cookiejar
- urllib.parse


#### 📜 Scripts Overview:

| Script Name                 | Purpose                                              | Type         | Threads | Platform Compatibility |
| --------------------------- | ---------------------------------------------------- | ------------ | ------- | ---------------------- |
| `dir_bruter.py`             | Directory & file bruteforcer using a wordlist        | Recon        | ✅ Yes   | ✅ Windows / ✅ Linux    |
| `form_bruter.py`            | Brute-force login forms via POST using HTML parsing  | Auth Attack  | ✅ Yes   | ✅ Windows / ✅ Linux    |
| `file_discovery_scanner.py` | Discover remotely accessible files from local mirror | Recon/Verify | ✅ Yes   | ✅ Windows / ✅ Linux    |



#### 🔎 Detailed Script Breakdown:

### 1️⃣ dir_bruter.py — 🛣️ Web Directory Brute Forcer
- Performs a directory and file brute-force attack against a given web server using multithreading and a custom wordlist.

### 🧩 Features:
- Supports extension bruteforcing: .php, .bak, .orig, .inc
- Queue-based wordlist processing with optional resume support
- Uses urllib3.PoolManager for efficient HTTP requests
- Prints only non-404 responses, meaning potential valid hits 🕵️‍♂️

```bash
python dir_bruter.py
```


### 2️⃣ form_bruter.py — 🔐 HTML Form Login Brute Forcer
- Brute-forces web-based login forms using POST requests and HTML parsing for dynamic input field discovery.

### 🧩 Features:
- Parses form inputs using html.parser 🧠
- Dynamically builds POST payload from form structure
- Multithreaded brute-forcing using a username and wordlist
- Detects login success via success string match (Administration - Control Panel)
- Uses cookies via http.cookiejar to manage sessions

```bash
python form_bruter.py
```

### 3️⃣ file_discovery_scanner.py — 🗂️ Remote File Discovery Tool
- Compares a local project directory with a remote web server by checking if files exist via HTTP GET requests.


### 🧩 Features:
- Scans the local directory recursively
- Skips static file types (.jpg, .css, .png, etc.)
- Multithreaded HTTP checks with clean output
- Useful for validating deployments and spotting leaked dev files

```bash
python file_discovery_scanner.py
```

### 📊 Script Comparison Table

| Feature / Script           | `dir_bruter.py` | `form_bruter.py` | `file_discovery_scanner.py` |
| -------------------------- | --------------- | ---------------- | --------------------------- |
| 🔍 Directory Enumeration   | ✅               | ❌                | ✅ (via mirror check)        |
| 🔑 Credential Brute-Force  | ❌               | ✅                | ❌                           |
| 📂 Local Folder Scan       | ❌               | ❌                | ✅                           |
| 🌐 Remote URL Validation   | ✅               | ✅ (login only)   | ✅                           |
| 🧩 File Extension Handling | ✅               | ❌                | ✅                           |
| 🧠 Form Parsing Support    | ❌               | ✅                | ❌                           |
| ⚙️ CLI Argument Support    | ❌               | ✅ (via input)    | ✅                           |
| ⚠️ Threaded Execution      | ✅               | ✅                | ✅                           |
| 💻 Cross-platform Support  | ✅               | ✅                | ✅                           |


### 🛠️ Setup & Execution:

## 1. Install required packages:

```bash
pip install urllib3
```

## 2. Run any script:

```bash
python dir_bruter.py

```

## or

```bash
python form_bruter.py

```
- 🚨 Make sure you have permission to test the target servers.

### 🧠 Learning Objectives Covered
- Performing web reconnaissance via directory and file enumeration 🕵️‍♀️
- Understanding how form authentication can be brute-forced via POST requests 🔑
- Mapping remote file exposure using local directory structure 📂
- Using Python’s html.parser, urllib3, and threading to simulate real-world tooling
- Building your own custom tools similar to DirBuster, Burp Suite, or WFuzz 🛠️

### 📬 Feedback
Have suggestions or improvements?
Open a pull request or reach out on GitHub Discussions 💬

#### Happy Hacking! 🧠💻🔥




