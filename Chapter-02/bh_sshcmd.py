import paramiko
import argparse
import getpass
import sys

def ssh_command(ip, user, password, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, username=user, password=password)
        ssh_session = client.get_transport().open_session()

        if ssh_session.active:
            ssh_session.exec_command(command)
            output = ssh_session.recv(4096).decode()
            print(f"[+] Command output:\n{output}")
            return output
        else:
            print("[-] SSH session failed to activate.")
    except paramiko.AuthenticationException:
        print("[-] Authentication failed! Check username/password.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Command Execution via Username/Password")
    parser.add_argument("ip", help="Target SSH IP address")
    parser.add_argument("user", help="SSH username")
    parser.add_argument("command", help="Command to execute on remote SSH machine")
    args = parser.parse_args()

    password = getpass.getpass("Enter SSH password: ")

    ssh_command(args.ip, args.user, password, args.command)




