# 📘 Chapter 3: Network Sniffing & Host Discovery — README

Welcome to **Chapter 3** of our blackhat-Python3 Series! 🚀 This chapter explores the **low-level internals of packet sniffing**, **ICMP response analysis**, and **active/passive scanning** — all built in Python using raw sockets, threading, and `ctypes`. 🧪🐍

---

> ⚠️ **Disclaimer**  
> This project is intended **for educational and authorized security testing purposes only**.  
> **Do not** use these scripts to scan or sniff networks **without explicit permission**.  
> Unauthorized use may violate **laws and regulations** and could lead to **legal consequences**.


## 🧰 Prerequisites

> ⚠️ **Admin/root privileges are required** to run raw sockets!

* Python 3.6+
* Run as Administrator (Windows) or with `sudo` (Linux/macOS)

### 📦 Libraries Used

```bash
pip install netaddr
```

* `socket`, `os`, `struct`, `argparse`, `threading`, `ctypes`
* External: `netaddr` (for subnet iteration and IP validation)

---

## 📜 Scripts Overview

| Script Name                | Purpose                                     | Protocols | Platform Compatibility |
| -------------------------- | ------------------------------------------- | --------- | ---------------------- |
| `scanner.py`               | Subnet-wide host discovery using UDP & ICMP | UDP, ICMP | ✅ Windows / ✅ Linux    |
| `packet_sniffer.py`        | Raw IP packet sniffer                       | IP/ICMP   | ✅ Windows / ✅ Linux    |
| `ip_sniffer_structured.py` | Structured IP header sniffing               | IP/ICMP   | ✅ Windows / ✅ Linux    |
| `icmp_packet_sniffer.py`   | Sniff & parse ICMP packets with details     | IP/ICMP   | ✅ Windows / ✅ Linux    |

---

## 🔎 Detailed Script Breakdown

### 1️⃣ `scanner.py` — 🧙‍♂️ Magic ICMP Scanner

Actively sends **UDP packets** and listens for ICMP replies to determine live hosts in a subnet.

```bash
python scanner.py --ip 192.168.1.10 --subnet 192.168.1.0/24
```

* Uses magic payload for accurate matching ✅
* Cross-platform promiscuous mode support 🦮

---

### 2️⃣ `packet_sniffer.py` — 🐍 Basic Raw Packet Sniffer

Captures raw IP packets from the network interface.

```bash
python packet_sniffer.py
```

* Simple and lightweight ⚖️
* Can be extended to parse headers
* Demonstrates core raw socket setup

---

### 3️⃣ `ip_sniffer_structured.py` — 🧠 IP Header Sniffer

Captures and decodes **IP headers** from live traffic.

```bash
python ip_sniffer_structured.py --host 192.168.1.100
```

* Parses source/destination IP and protocol
* Uses `ctypes.Structure` for clean IP parsing
* Displays continuous flow of packets ✨

---

### 4️⃣ `icmp_packet_sniffer.py` — 📡 Detailed ICMP Sniffer

Full-fledged sniffer that filters and parses **ICMP packets**:

```bash
python icmp_packet_sniffer.py
```

* Parses ICMP header fields: `Type`, `Code`, `Checksum`
* Only logs ICMP packets from traffic
* Shows full protocol + IP info per packet 🦮

---

## 📊 Script Comparison Table

| Feature / Script              | `scanner.py` | `packet_sniffer.py` | `ip_sniffer_structured.py` | `icmp_packet_sniffer.py` |
| ----------------------------- | ------------ | ------------------- | -------------------------- | ------------------------ |
| 🔍 ICMP Parsing               | ✅            | ❌                   | ❌                          | ✅                        |
| 🌐 Subnet Scan                | ✅            | ❌                   | ❌                          | ❌                        |
| 📦 IP Header Parsing          | ✅            | Partial             | ✅                          | ✅                        |
| 🧙‍♂️ Magic Payload Filtering | ✅            | ❌                   | ❌                          | ❌                        |
| ⚙️  CLI Argument Support      | ✅            | ❌                   | ✅                          | ✅                        |
| 🎯 Targeted Host Input        | ✅            | ✅                   | ✅                          | ✅                        |
| 📦 Packet Size Check          | ✅            | ❌                   | ✅                          | ✅                        |
| ⚠️ Root/Admin Required        | ✅            | ✅                   | ✅                          | ✅                        |
| 💻 Cross-platform Support     | ✅            | ✅                   | ✅                          | ✅                        |

---

## 🛠️ Setup & Execution

### 1. Install requirements (only one external library):

```bash
pip install netaddr
```

### 2. Run any script with Python 3:

```bash
sudo python scanner.py --ip 192.168.1.10 --subnet 192.168.1.0/24
```

---

## 🧠 Learning Objectives Covered

* Understanding **raw socket programming** 📦
* Parsing IP and ICMP headers using `ctypes` 🦮
* Passive sniffing vs. active scanning 🌐
* Practical experience with cross-platform sniffers ⚙️
* Building foundations for tools like **Nmap**, **Wireshark**, or **Snort**

---

## 🧹 Next Steps

In future chapters, you will:

* Analyze TCP streams
* Build a packet injector 🔫
* Construct a mini IDS/IPS system

> 🚀 You're now equipped with Python-powered visibility into raw packets flowing across your network!

---

## 📬 Feedback

Have suggestions or improvements? Open a pull request or reach out on GitHub Discussions 💬

---

Happy Sniffing! \\
