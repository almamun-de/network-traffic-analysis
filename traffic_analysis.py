from scapy.all import sniff, IP, TCP, UDP

# Define a function to analyze captured packets
def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\nPacket captured: {packet.summary()}")
        print(f"Source IP: {ip_src}")
