import zlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

encrypted_b64 = ""  # Insert your base64 string here

# --- RSA Private Key ---
private_key = """ Enter your RSA private key here for Decryption. """

# --- Decryption ---
try:
    rsakey = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(rsakey)

    encrypted_bytes = base64.b64decode(encrypted_b64)
    chunk_size = 256
    offset = 0
    decrypted_data = b""

    while offset < len(encrypted_bytes):
        decrypted_chunk = cipher.decrypt(encrypted_bytes[offset:offset + chunk_size])
        decrypted_data += decrypted_chunk
        offset += chunk_size

    plaintext = zlib.decompress(decrypted_data)
    print("[+] Decrypted and decompressed content:")
    print(plaintext.decode('utf-8', errors='ignore'))

except Exception as e:
    print(f"[-] Error during decryption or decompression: {e}")
