# Network Sniffer with Credential Detector

A network sniffer tool that captures and analyzes network traffic to identify cleartext credentials transmitted via HTTP and FTP protocols. This project demonstrates network-level data interception and the risks of using unencrypted channels for communication.

## Running the program

1. Run the command prompt as administrator.
2. Install scapy if it is not yet installed on the machine:
   ```bash
   pip install scapy
   ```
3. Run using the following commands:

   ### Basic Usage
   ```bash
   python packet_sniffer.py -i <interface>
   ```

   ### With Duration:
   ```bash
   python packet_sniffer.py -i <interface> -t <duration_in_seconds>
   ```

   ### With Packet Count:
   ```bash
   python packet_sniffer.py -i <interface> -c <packet_count>
   ```

   ### With Duration and Packet Count:
   ```bash
   python packet_sniffer.py -i <interface> -t <duration_in_seconds> -c <packet_count>
   ```

## Features

### Live Network Packet Capture
- Captures packets on the specified network interface
- Uses scapy for packet analysis

### Credential Extraction and Logging
- Extracts usernames and passwords from HTTP POST parameters and FTP USER and PASS commands
- Logs all detected credentials with additional information such as timestamps and source/destination IPs
- Saves detected credentials to the `credentials_log.txt` file

### Capture Control Options
- Provides additional options to limit packet captures in terms of duration and number of packets where:
  - `-t`: Specifies capture duration in seconds
  - `-c`: Specifies number of packets to process
- Handles Ctrl + C interruption

### Summary Report
- Lists all the credentials that were detected throughout the session

