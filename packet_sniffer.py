"""
Network Sniffer with Credential Detector
Group 1 - Project Implementation

This tool captures and analyzes network traffic to identify cleartext credentials
transmitted via HTTP and FTP protocols in a controlled lab environment.
"""

import scapy.all as scapy
import argparse
from scapy.layers import http
from scapy.layers.inet import TCP
import time
import re
from datetime import datetime

# BASED ON SPECS: All captured credentials and relevant packet details (source IP, destination IP, timestamp) must be saved to a local log file
LOG_FILE = "credentials_log.txt"

def get_interface():
    """
    BASED ON SPECS: The program must allow the user to specify the capture duration or the number of packets to process before stopping.
    Parse command line arguments for network interface, duration, and packet count
    """
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-t", "--time", type=int, default=0, help="Duration to sniff (seconds)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff")
    args = parser.parse_args()
    return args.interface, args.time, args.count

def log_credential(creds):
    """
    BASED ON SPECS:
    - All captured credentials and relevant packet details (source IP, destination IP, timestamp) must be saved to a local log file.
    - The program must handle exceptions gracefully (e.g., permissions issues or unavailable interfaces) and notify the user.
    """
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
    """
    BASED ON SPECS: All captured credentials and relevant packet details (source IP, destination IP, timestamp) must be saved to a local log file.
    """
    return {
        'protocol': protocol,
        'src': packet[scapy.IP].src,
        'dst': packet[scapy.IP].dst,
        'timestamp': timestamp,
        'username_fields': username_fields,
        'password_fields': password_fields
    }
        
def process_packet(packet):
    """
    BASED ON SPECS:
    - The tool must filter and analyze network traffic for unencrypted protocols such as HTTP and FTP.
    - The tool must extract and log sensitive information such as usernames and passwords found in:
      o HTTP POST request parameters (e.g., login forms).
      o FTP commands for user authentication (e.g., USER and PASS commands).
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    # BASED ON SPECS: The tool must extract and log sensitive information such as usernames and passwords found in HTTP POST request parameters (e.g., login forms).
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode(errors="ignore")
        path = packet[http.HTTPRequest].Path.decode(errors="ignore")
        print(f"[+] HTTP Request >> {host}{path}")
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            user_fields = re.findall(r"(username|user|email|login|uid|id)=([^&\s]+)", load, re.I)
            pass_fields = re.findall(r"(password|pass|pwd|passw|secret)=([^&\s]+)", load, re.I)
            if user_fields or pass_fields:
                creds = create_creds('HTTP', packet, timestamp, user_fields, pass_fields)
                log_credential(creds)
                print(f"[HTTP] Credentials Detected: {creds}")
                
    # BASED ON SPECS: The tool must extract and log sensitive information such as usernames and passwords found in FTP commands for user authentication (e.g., USER and PASS commands).
    elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            
            # Checks for FTP USER and PASS commands
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
            
            # FTP File Transfer Commands
            ftp_commands = [
                "STOR", "RETR", "PUT", "GET", "LIST", "LS", "PWD", "CWD", "CDUP",
                "MKD", "RMD", "DELE", "RNFR", "RNTO", "SIZE", "MDTM"
            ]
            
            for cmd in ftp_commands:
                if cmd in load:
                    operation_info = f"[FTP_OP] {timestamp} | {packet[scapy.IP].src} -> {packet[scapy.IP].dst} | Command: {load.strip()}"
                    print(f"[+] FTP Operation detected: {operation_info}")
                    log_ftp_operation(operation_info)
                    break

def main():
    """
    BASED ON SPECS:
    - The tool must capture live network packets on a specified network interface within a controlled lab environment.
    - The program must allow the user to specify the capture duration or the number of packets to process before stopping.
    - The program must handle exceptions gracefully (e.g., permissions issues or unavailable interfaces) and notify the user.
    - The tool should provide a summary of detected credentials at the end of the capture session.
    """
    iface, duration, count = get_interface()
    print(f"Sniffing on {iface}... (duration: {duration}s, count: {count})")
    
    # BASED ON SPECS: The tool must capture live network packets on a specified network interface within a controlled lab environment.
    try:
        # To avoid socket errors
        sniff_params = {
            'iface': iface,
            'store': False,
            'prn': process_packet
        }
        
        if duration > 0:
            sniff_params['timeout'] = duration
        if count > 0:
            sniff_params['count'] = count
            
        scapy.sniff(**sniff_params)
        
    except PermissionError:
        print("[!] Permission denied. Run as root/administrator.")
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

    # BASED ON SPECS: The tool should provide a summary of detected credentials at the end of the capture session.
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

