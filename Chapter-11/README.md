# Chapter 11: Fun with DLLs and Code Injection

Welcome to Chapter 11 of the **Black Hat Python** project repository. This chapter explores advanced techniques for analyzing and manipulating live processes, memory, and registry hives. Here, we leverage tools like **Immunity Debugger** and **Volatility** to inject, trace, and extract critical runtime and registry data from target systems.

---

## 📁 Scripts in This Chapter

### 1. `calc_hook_trace.py`

**Purpose:**
Hooks and logs execution of all functions within the `calc.exe` process using **Immunity Debugger**.

**Key Features:**

* Attaches to the `calc.exe` process
* Sets breakpoints on all discovered functions
* Logs execution of hooked functions

**Use Case:**
This is useful for tracing execution flow or identifying which functions are being triggered during runtime.

---

### 2. `volatility_mem_shellcode_inject.py`

**Purpose:**
Injects custom shellcode into the memory space of a running `calc.exe` process from a captured memory image using **Volatility**.

**Key Features:**

* Scans for slack space in the memory image
* Injects shellcode at a discovered slack location
* Overwrites function code with a trampoline to redirect execution

**Use Case:**
Enables stealthy code injection and redirection by modifying a memory image directly. Ideal for malware analysis or forensic red-teaming scenarios.

---

### 3. `memory_sam_hashdump.py`

**Purpose:**
Extracts Windows user password hashes from a memory dump by parsing the **SAM** and **SYSTEM** registry hives.

**Key Features:**

* Identifies SAM and SYSTEM registry hives in memory
* Uses Volatility's `HashDump` plugin to extract NTLM hashes

**Use Case:**
An effective tool for red teamers and forensic analysts to retrieve credential artifacts from volatile memory.

---

## 🧠 Concepts Demonstrated

* Runtime hooking with `Immunity Debugger`
* Shellcode injection via slack space
* Memory image analysis with Volatility
* Registry hive enumeration and parsing
* Extracting credential artifacts from volatile memory

---

## 🧰 Requirements

* Python 2.7 (for compatibility with Volatility 2)
* [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
* [Volatility 2.3.1](https://github.com/volatilityfoundation/volatility)
* A memory image (e.g., `WinXPSP2.vmem`, `Windows Server 2003.vmem`)

---

## ⚠️ Disclaimer

This code is provided for **educational and research purposes only**. Unauthorized use of these tools on systems without explicit permission is illegal and unethical.

---

## 📎 Additional Notes

* Use VMware or VirtualBox for safely generating memory images.
* Shellcode used in this chapter is stored in a binary file (e.g., `cmeasure.bin`).
* Always back up your memory images before performing write operations.

---

Happy Hacking! ✨🚀

