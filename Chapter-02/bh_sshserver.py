import socket
import paramiko
import threading
import os
import argparse
import subprocess
import sys

# Path to authorized keys file (can be customized)
authorized_keys_file = os.path.expanduser("~/.ssh/authorized_keys")

class CustomSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        try:
            with open(authorized_keys_file, 'r') as f:
                if key.get_base64() in f.read():
                    print(f"[+] Public key authentication succeeded for user: {username}")
                    return paramiko.AUTH_SUCCESSFUL
        except FileNotFoundError:
            print("[!] Authorized keys file not found.")
        return paramiko.AUTH_FAILED


def start_ssh_server(host, port, private_key_path):
    if not os.path.exists(private_key_path):
        print(f"[!] Private key file not found: {private_key_path}")
        sys.exit(1)

    host_key = paramiko.RSAKey(filename=private_key_path)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        print(f"[+] Listening on {host}:{port}...")
        client, addr = sock.accept()
    except Exception as e:
        print(f"[!] Failed to bind or accept connection: {e}")
        sys.exit(1)

    print(f"[+] Connection from {addr}")

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = CustomSSHServer()
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            raise Exception("[-] Channel creation failed.")

        print("[+] Authenticated! Ready to receive commands.")
        chan.send("Welcome to the custom SSH server!\n")

        while True:
            command = chan.recv(1024).decode().strip()
            if not command or command.lower() == 'exit':
                chan.send("Session closed.\n")
                chan.close()
                print("[*] Session closed by client.")
                break

            print(f"[+] Command received: {command}")
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                chan.send(output)
            except subprocess.CalledProcessError as e:
                chan.send(f"Error executing command:\n{e.output.decode()}")
    except Exception as e:
        print(f"[!] SSH server error: {e}")
    finally:
        try:
            transport.close()
            sock.close()
        except Exception as cleanup_error:
            print(f"[!] Cleanup error: {cleanup_error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom Paramiko SSH Server")
    parser.add_argument("host", help="IP address to bind the SSH server")
    parser.add_argument("port", type=int, help="Port to bind the SSH server")
    parser.add_argument("private_key", help="Path to the private RSA key file")
    args = parser.parse_args()

    start_ssh_server(args.host, args.port, args.private_key)
