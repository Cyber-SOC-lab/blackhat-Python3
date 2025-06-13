import socket
import os
import sys

def get_local_host():
    host = input("Enter the host IP to bind to (e.g., 192.168.0.196): ").strip()
    if not host:
        print("[!] Host IP is required.")
        sys.exit(1)
    return host

def create_sniffer(host):
    # Choose protocol based on OS
    if os.name == "nt":
        protocol = socket.IPPROTO_IP
    else:
        protocol = socket.IPPROTO_ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    except PermissionError:
        print("[!] Permission denied: Run this script as Administrator/root.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to create raw socket: {e}")
        sys.exit(1)

    try:
        sniffer.bind((host, 0))
    except socket.error as e:
        print(f"[!] Failed to bind to host {host}: {e}")
        sys.exit(1)

    # Include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Windows requires IOCTL to enable promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    return sniffer

def main():
    host = get_local_host()
    sniffer = create_sniffer(host)

    print(f"[*] Sniffing on {host}... Press Ctrl+C to stop.\n")
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            print(f"[+] Packet received from {addr[0]}:{addr[1]} - {len(raw_data)} bytes")
            print(raw_data[:64].hex(), "...\n")  # Print first 64 bytes for preview
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer...")

    # Disable promiscuous mode on Windows
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    sniffer.close()

if __name__ == "__main__":
    main()
