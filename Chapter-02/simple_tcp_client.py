import socket

def get_user_input():
    target_host = input("Enter target host (e.g., www.google.com): ").strip()
    port_input = input("Enter target port (default 80): ").strip()

    if not target_host:
        print("[!] Target host cannot be empty.")
        exit(1)

    try:
        target_port = int(port_input) if port_input else 80
        if target_port <= 0 or target_port > 65535:
            raise ValueError
    except ValueError:
        print("[!] Invalid port number. Must be between 1 and 65535.")
        exit(1)

    return target_host, target_port


def main():
    target_host, target_port = get_user_input()

    # Create a TCP socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            print(f"[*] Connecting to {target_host}:{target_port} ...")
            client.connect((target_host, target_port))

            # Send HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
            client.send(request.encode())

            # Receive and print the response
            response = b""
            while True:
                part = client.recv(4096)
                if not part:
                    break
                response += part

            print("\n[+] Response received:\n")
            print(response.decode(errors="replace"))

    except socket.gaierror:
        print(f"[!] Hostname resolution failed for: {target_host}")
    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
