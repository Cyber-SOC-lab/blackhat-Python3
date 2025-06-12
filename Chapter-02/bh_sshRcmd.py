import paramiko
import os
import argparse
import sys

def ssh_command(ip, port, user, private_key_file, command):
    try:
        private_key = paramiko.RSAKey(filename=private_key_file)
    except Exception as e:
        print(f"[!] Failed to load private key: {e}")
        sys.exit(1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[*] Connecting to {ip}:{port} as {user}...")
        client.connect(ip, port=port, username=user, pkey=private_key)
        ssh_session = client.get_transport().open_session()

        if ssh_session and ssh_session.active:
            ssh_session.exec_command(command)
            output = ssh_session.recv(4096).decode()
            print("[+] Command Output:\n", output)
        else:
            print("[!] SSH session is not active.")
    except paramiko.AuthenticationException:
        print("[!] Authentication failed. Check your credentials or key file.")
    except Exception as e:
        print(f"[!] SSH connection error: {e}")
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="Execute a command on a remote SSH server using a private key.")
    parser.add_argument("--ip", required=True, help="Target SSH server IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--key", required=True, help="Path to private key file (RSA format)")
    parser.add_argument("--command", required=True, help="Command to execute on the remote machine")

    args = parser.parse_args()

    ssh_command(args.ip, args.port, args.user, os.path.expanduser(args.key), args.command)


if __name__ == "__main__":
    main()
