# 📘 Chapter 4: Passive Reconnaissance & Packet Sniffing — README

Welcome to **Chapter 4** of our Python Networking Series! 🕵️‍♂️  
In this chapter, we dive into **Man-in-the-Middle attacks**, **email credential sniffing**, and **HTTP image carving** — using tools like `scapy`, `kamene`, and `OpenCV`. These scripts reveal just how exposed plaintext protocols and unencrypted traffic can be! 🔍💣

---

## ⚠️ Legal Disclaimer

> ⚠️ **USE RESPONSIBLY — FOR EDUCATIONAL PURPOSES ONLY!**  
> These scripts are designed to **demonstrate real-world security flaws** and are to be run **only on networks you own or have permission to test**.  
> Unauthorized use of these tools is **illegal and unethical**.

---

## 🧰 Prerequisites

> ⚠️ **Admin/root privileges are required** to sniff traffic and perform ARP poisoning!

* Python 3.6+
* Run with `sudo` or as Administrator

### 📦 Libraries Used

- scapy
- kamene
- OpenCV
- threading
- zlib
- re
  

### 📜 Scripts Overview:

| Script Name                  | Purpose                                     | Protocols  | Execution Mode | Output Type                 |
| ---------------------------- | ------------------------------------------- | ---------- | -------------- | --------------------------- |
| `arp_poison_sniffer.py`      | ARP spoofing MITM + packet sniffer          | ARP + IP   | Real-time      | `arp_test.pcap`             |
| `email_sniffer.py`           | Extract credentials from unencrypted email  | POP3, SMTP | Real-time      | Console output              |
| `image_carver_with_faces.py` | Extract HTTP images + detect faces in PCAPs | HTTP       | Offline        | `.jpg` files (images/faces) |



##### 🔎 Detailed Script Breakdown:

### 1️⃣ arp_poison_sniffer.py — 🧠 Man-in-the-Middle + Sniff
- A *multi-threaded* MITM tool that uses ARP spoofing to intercept traffic between a target host and its gateway. It captures all the traffic into a *.pcap* file.

### ✅ Features:
- ARP cache poisoning of the target and gateway
- Traffic sniffing with BPF filter
- Automatic ARP restoration on exit
- Packet output saved as arp_test.pcap

```bash
sudo python arp_poison_sniffer.py
```

### 2️⃣ email_sniffer.py — 📨 POP3/SMTP/IMAP Credential Extractor
- A focused sniffer to monitor email traffic and extract any login attempts over plaintext protocols like POP3, SMTP, and IMAP.

### ✅ Features:
- Filters ports 110, 25, and 143
- Extracts user and pass from TCP payloads
- Useful for testing insecure mail configurations

❗ Email credentials over plaintext = serious risk!

```bash
sudo python email_sniffer.py
```

### 3️⃣ image_carver_with_faces.py — 🖼️ HTTP Image Rebuilder + Face Detector
- An offline analyzer that carves images from HTTP traffic in a .pcap file, and uses OpenCV to detect and annotate any faces found in the images.

### ✅ Features:
- Parses .pcap for HTTP image content
- Decompresses gzip/deflate if needed
- Detects faces using Haar cascades
- Stores results in pic_carver/pictures and pic_carver/faces

### 📂 Example Output:
- pic_carver/pictures/bhp-pic_carver_0.jpg
- pic_carver/faces/bhp.pcap-bhp-pic_carver_0.jpg


```bash
python image_carver_with_faces.py  
```

#### 📊 Script Comparison:

| Feature / Script         | `arp_poison_sniffer.py` | `email_sniffer.py` | `image_carver_with_faces.py` |
| ------------------------ | ----------------------- | ------------------ | ---------------------------- |
| 📡 Protocol Scope        | All IP via MITM         | POP3/SMTP/IMAP     | HTTP                         |
| 💻 Live Network Required | ✅ Yes                   | ✅ Yes              | ❌ Offline (PCAP required)    |
| 🧪 MITM Poisoning        | ✅ Yes                   | ❌ No               | ❌ No                         |
| 🔍 Credential Discovery  | ❌ No                    | ✅ Yes              | ❌ No                         |
| 🖼️ Image Extraction     | ❌ No                    | ❌ No               | ✅ Yes                        |
| 🤖 Face Detection        | ❌ No                    | ❌ No               | ✅ Yes                        |
| 📁 Output Type           | `.pcap` file            | Console Log        | JPEG Images                  |
| 🔁 Auto Cleanup          | ✅ ARP restored          | ❌ No               | ❌ No                         |
| 🧠 Parsing Layer         | IP/ARP + BPF Filter     | TCP Payload        | HTTP Header + Payload        |
| ⚠️ Requires Root/Admin   | ✅ Yes                   | ✅ Yes              | ⚠️ Only for packet capture   |



##### 🛠️ Setup & Execution:
### 1. Install dependencies:

```bash
pip install scapy kamene opencv-python

```

### 2. Run any script:

```bash
# Example 1: Live ARP poisoning and sniffing
sudo python arp_poison_sniffer.py

# Example 2: Sniff plaintext email credentials
sudo python email_sniffer.py

# Example 3: Carve images and detect faces from a PCAP file
python image_carver_with_faces.py
```

##### 🧠 Learning Objectives Covered
- 🔍 Understanding how ARP spoofing works to intercept traffic
- 📨 Identifying insecure email protocols in the wild
- 🖼️ Reconstructing web content using HTTP parsing
- 🤖 Performing face detection with OpenCV
- 💾 Working with .pcap files for forensic inspection



#### 💬 Feedback
- Got improvements or questions?
- Submit a pull request or post on our GitHub Discussions page! 🚀


