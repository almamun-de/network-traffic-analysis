
from scapy.all import sniff, IP, TCP, UDP

# Define a function to analyze captured packets
def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\nPacket captured: {packet.summary()}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")

        # Check if it's a TCP or UDP packet
        if protocol == 6 and TCP in packet:  # Protocol 6 is TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        elif protocol == 17 and UDP in packet:  # Protocol 17 is UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        else:
            print("Other protocol detected.")

# Start sniffing for network packets
def start_sniffing(interface=None):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    # Modify this if you want to specify a network interface (e.g., "eth0", "wlan0")
    start_sniffing(interface=None)  # By default, it'll sniff on all interfaces
