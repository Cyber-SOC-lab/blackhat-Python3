# 🐍 BlackHat-Python3

> 💻 Updated source code from the book *Black Hat Python* by Justin Seitz, fully converted to Python 3 with compatibility, structure, and enhancements in mind.

---

## 📚 Book Overview

This repository contains the full source code for the book [**Black Hat Python**](https://nostarch.com/blackhatpython) by Justin Seitz, rewritten and upgraded for modern Python 3 environments.

> *“When it comes to offensive security, having your own custom tools can be a game changer. Black Hat Python shows you how to harness the full power of Python for hacking and penetration testing.”*

The original code base was primarily written for Python 2, which is now deprecated. This repository upgrades that code to Python 3, replaces deprecated libraries with maintained alternatives, applies PEP8 formatting, and fixes bugs and compatibility issues — all while preserving the book's original structure and learning intent.

---

## ✨ Project Highlights

### ✅ What’s New?

- ✔️ **Fully converted to Python 3**
- 🔁 **PEP8 formatting applied across all files**
- 🚫 **Deprecated libraries replaced** (e.g., `urllib`, `SocketServer`, `imp`, etc.)
- 🐞 **Fixed indentation, runtime, and logic errors**
- 📦 **Added missing scripts and auxiliary files**
- 📁 **Reorganized chapters into structured directories**
- 🧪 **Tested and verified against modern Python (3.10+)**

### 🛠️ Key Improvements

- Use of `socketserver`, `subprocess`, `threading`, and `selectors` modules for modern concurrency and networking.
- Switched from `raw_input()` to `input()` and from `print` statements to Python 3 print functions.
- Added support for `venv` virtual environments and `requirements.txt` for dependency management.
- Introduced better exception handling and safer file operations (e.g., using `with` context managers).
- Cleaned up and updated memory analysis, malware simulation, and hooking techniques for compatibility with modern systems where feasible.

---

## 🧭 Repository Structure

Each chapter of the book is placed in its own folder and contains all relevant scripts, helper files, and a dedicated `README.md` that documents the contents.



---

## ⚙️ Usage

To get started with this project, use the following steps:

```bash
# Clone the repository
git clone https://github.com/YourUsername/blackhat-python3.git
cd blackhat-python3

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # On Windows use: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

> 📌 Some chapters include platform-specific scripts (e.g., Windows-only), or require admin privileges or debugging tools like Immunity Debugger or Volatility.



---


## 🗒️ Notes & Clarifications

- Some listings were missing from the original code archive provided by No Starch Press and have been restored or recreated where appropriate.

- Filenames have been revised for consistency and clarity while matching their corresponding sections in the book.

- Auxiliary or helper files (e.g., VBS payloads, shellcode binaries) are included in their respective directories.

- Several low-level exploits (DLL injection, memory forensics, etc.) have been adapted to support Windows 10/11 or newer versions of Volatility where applicable.



---


## 🧠 Educational Value

While enhancements were applied to ensure functionality and modern compatibility, we’ve maintained the original structure, minimalism, and “bare-metal” Python coding style of the book. Readers are encouraged to:

- Add docstrings and type hints.
- Implement error handling and logging.
- Refactor code to use OOP or functional paradigms.
- Convert scripts into reusable tools.

This approach preserves the **learning-by-building** philosophy of Black Hat Python.

---

## 👨‍💻 Repository Maintainer & Python 3 Conversion

This Python 3 port and modernization effort was completed by [Cyber-SOC-lab].
All scripts have been reviewed, refactored, and tested for educational use in modern ethical hacking labs.

Inspired by similar conversion work (e.g., by EONRaider) and extended with deeper compatibility fixes.

---


## ⚠️ Disclaimer

This repository is for educational purposes only. Use of any code from this book must follow all applicable laws and ethical guidelines. The author and contributors are not responsible for any misuse or damage caused by improper use of these tools.


---


## 📬 Feedback & Contributions


Have suggestions, improvements, or spotted an issue?
Feel free to open an issue or submit a pull request.


---


## 🏁 Final Note

> “Black Hat Python doesn’t just teach you how to write scripts — it teaches you how to think like a hacker.”

Explore the chapters, understand the code, improve what you can, and learn deeply by building hands-on.

**Happy Hacking! 🕶️🐍**
