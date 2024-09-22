# Network Traffic Analysis Tool

This is a simple network traffic analysis tool written in Python that captures and analyzes network packets in real time. It uses the `scapy` library to detect the source and destination IP addresses, ports, and protocols of captured packets.

## Features
- Captures network traffic on any specified network interface.
- Identifies source and destination IP addresses.
- Detects TCP and UDP packets and displays their respective ports.
- Can be extended to perform deeper packet analysis.

## Requirements
- Python 3.x
- `scapy` library

Install dependencies using the following command:
```bash
pip install -r requirements.txt

Run the script to start capturing packets:
sudo python traffic_analysis.py

If you want to specify a network interface, you can modify the start_sniffing function in traffic_analysis.py to something like:
start_sniffing(interface="eth0")  # Replace with your network interface name
```

How the Script Works
Sniffing: The script uses scapy to sniff network packets on a specified or default network interface.
Packet Analysis: For each packet, it extracts and prints key information such as:
Source and destination IP addresses.
Protocol type (TCP, UDP, or other).
Ports for TCP and UDP packets.
Installation & Running
Make sure you have the scapy library installed and run the script with sudo as it requires elevated permissions to capture network traffic.
Extensibility
You can extend the script to detect other types of traffic such as ARP, ICMP, or even analyze packet payloads.
Add filtering options to only capture packets from certain IPs or ports.
