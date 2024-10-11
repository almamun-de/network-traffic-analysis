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
