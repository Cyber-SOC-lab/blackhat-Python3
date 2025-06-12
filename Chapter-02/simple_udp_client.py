import socket

def get_user_input():
    target_host = input("Enter target host (e.g., 127.0.0.1): ").strip()
    port_input = input("Enter target port (default 9999): ").strip()

    if not target_host:
        print("[!] Target host cannot be empty.")
        exit(1)

    try:
        target_port = int(port_input) if port_input else 9999
        if target_port <= 0 or target_port > 65535:
            raise ValueError
    except ValueError:
        print("[!] Invalid port number. Must be between 1 and 65535.")
        exit(1)

    return target_host, target_port

def main():
    target_host, target_port = get_user_input()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            message = input("Enter message to send: ").strip() or "Hello via UDP"

            print(f"[*] Sending UDP packet to {target_host}:{target_port} ...")
            client.sendto(message.encode(), (target_host, target_port))

            client.settimeout(3.0)
            try:
                data, server = client.recvfrom(4096)
                print(f"[+] Response from {server[0]}:{server[1]}:\n{data.decode(errors='replace')}")
            except socket.timeout:
                print("[!] No response received (timeout).")

    except socket.gaierror:
        print(f"[!] Hostname resolution failed for: {target_host}")
    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()
