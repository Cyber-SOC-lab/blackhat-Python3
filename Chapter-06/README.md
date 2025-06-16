# Chapter 6 - Burp Suite Automation (Black Hat Python)

## Overview

This chapter demonstrates how to create Burp Suite extensions using Python (Jython) for automating tasks such as payload generation, external reconnaissance via Bing search, and building custom wordlists from HTML responses.

Burp Suite is a powerful tool for web application testing, and these scripts allow you to integrate custom logic to augment Intruder, Scanner, and other components.

> **Warning**: These tools are intended for **authorized security testing and learning purposes only**. Do **not** use them against systems you do not own or have explicit permission to test. Misuse can lead to legal consequences.

---

## 🔧 Requirements & Dependencies

### Burp Suite Setup

* [Burp Suite Community or Professional Edition](https://portswigger.net/burp)
* [Jython Standalone Jar](https://www.jython.org/download.html)

### How to Install Jython in Burp

1. Download the `jython-standalone-2.7.x.jar`.
2. Open Burp Suite > Extender > Options > Python Environment.
3. Set the path to the downloaded Jython jar.

### How to Load Scripts

1. Go to **Extender > Extensions**.
2. Click **Add**.
3. Extension Type: **Python**.
4. Load the `.py` script file.
5. The script will automatically register its functionality in Burp.

---

## 📜 Script 1: `bhp_intruder_fuzzer.py`

### Functionality

* Custom Intruder Payload Generator
* Mutates payloads using common injection patterns:

  * SQL injection (`'`)
  * XSS payloads (`<script>alert()`)
  * Repetition attacks (duplicating chunks of input)

### Features

* Injects randomized mutated payloads
* Works seamlessly with Burp Intruder
* No external dependencies

### How to Use

1. Load the script via **Extender > Extensions**.
2. Go to **Intruder > Positions**, highlight fields for payload injection.
3. In **Payloads** tab, select **Payload Type: BHP Payload Generator**.
4. Launch the attack.

---

## 📜 Script 2: `bhp_bing_lookup.py`

### Functionality

* Context-menu extension that performs Bing API lookups
* Enumerates subdomains and related hosts via:

  * IP address queries
  * Domain-based searches

### Features

* Adds "Send to Bing" to the Burp right-click menu
* Retrieves up to 20 results from Bing Web Search
* Automatically adds discovered hosts to Burp Scope

### Prerequisites

* Requires **Bing Web Search API Key**
* Replace `bing_api_key = "YOURKEYHERE"` with your valid API key

> **Note:** Bing Search API v2 is deprecated. Consider alternatives like [Bing Search v7 on Azure](https://learn.microsoft.com/en-us/bing/search-apis/).

### How to Use

1. Load script in Burp Extender.
2. Right-click on any HTTP request > **Send to Bing**.
3. Script performs API call and prints matching domains/hosts in output.

---

## 📜 Script 3: `bhp_wordlist.py`

### Functionality

* Builds a custom wordlist from HTTP response content
* Extracts:

  * HTML text content
  * HTML comments

### Features

* Adds **"Create Wordlist"** to context menu
* Collects unique keywords from all highlighted requests
* Helps in discovering usernames, passwords, parameters

### How to Use

1. Highlight multiple HTTP requests/responses.
2. Right-click > **Create Wordlist**.
3. Script processes HTML content and displays wordlist in output.

---

## 🧪 Testing Methodology

### General Setup

1. Install Burp Suite and configure proxy.
2. Load each script via Extender tab as needed.
3. Capture HTTP traffic using Burp Proxy.
4. Use respective context-menu or Intruder functionality as described above.
5. View results/output in the **Extender > Output** panel.

### Testing Tips

* Use test web apps like DVWA, Juice Shop, or WebGoat for safe experimentation.
* Make sure to replace placeholder API keys (for Bing search).
* Inspect Intruder results to see the effect of payload mutations.

---

## ⚠️ Legal Disclaimer

> These scripts and techniques are provided for **educational and authorized penetration testing** purposes only. Unauthorized use against third-party systems or networks may violate laws and ethical guidelines. Always obtain **written permission** before conducting security testing on any target.

---

## 📁 Files in This Chapter

| Script Name                | Description                                         |
| -------------------------- | --------------------------------------------------- |
| `bhp_intruder_fuzzer.py` | Mutates input data for fuzzing attacks via Intruder |
| `bhp_bing_lookup.py`       | Queries Bing API for domain/IP intelligence         |
| `bhp_wordlist.py`  | Builds a custom wordlist from HTTP response content |

---

## ✅ Summary

Chapter 6 focuses on using Burp Suite extensibility to automate parts of web application testing. These Python-based (Jython) scripts serve as examples of how to:

* Extend Burp's capabilities
* Build useful tools for reconnaissance and fuzzing
* Improve penetration testing efficiency

You now have a foundational understanding of scripting Burp extensions. Be ethical, and happy hacking!

---

Feel free to enhance or expand upon these tools to match your testing workflows.
