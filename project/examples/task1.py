from scapy.all import sniff, IP, TCP, UDP, wrpcap

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print("\n=== Sniffed packet ===")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
            src_port = layer.sport
            dst_port = layer.dport
            proto = "TCP" if packet.haslayer(TCP) else "UDP"
            print(f"{proto}: Source port: {src_port}. Destination port: {dst_port}")
        else:
            print("Unknown transport layer")

packets = sniff(filter="ip", prn=packet_callback, count=10)
wrpcap("./project/pcaps-private/sniffed_packets-task1.pcap", packets)