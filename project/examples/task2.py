from scapy.all import rdpcap, Ether, IP, TCP, UDP, DNS, ARP, ICMP, BOOTP, STP, IP, IPv6

# Load network capture file
packets = rdpcap("./project/pcaps/FIRST-2015_Hands-on_Network_Forensics_PCAP/2015-04-13/snort.log.1428883207")

protocols = {
    "TCP": lambda pkt: pkt.haslayer(TCP),
    "UDP": lambda pkt: pkt.haslayer(UDP),
    "DNS": lambda pkt: pkt.haslayer(DNS),
    "ARP": lambda pkt: pkt.haslayer(ARP),
    "ICMP": lambda pkt: pkt.haslayer(ICMP),
    "BOOTP/DHCP": lambda pkt: pkt.haslayer(BOOTP),
    "STP": lambda pkt: pkt.haslayer(STP), 
    "IPv4": lambda pkt: pkt.haslayer(IP),
    "IPv6": lambda pkt: pkt.haslayer(IPv6),
    "Ethernet": lambda pkt: pkt.haslayer(Ether)
}

filtered_packets = { proto: [] for proto in protocols }

for packet in packets:
    for protocol, condition in protocols.items():
        if condition(packet):
            filtered_packets[protocol].append(packet)

for proto, pkts in filtered_packets.items():
    print(f"{proto}: {len(pkts)} packets")

print("==================================================")
# TCP & UDP:
tcp_count = len(filtered_packets["TCP"])
udp_count = len(filtered_packets["UDP"])

total_packets = tcp_count + udp_count

tcp_ratio = (tcp_count / total_packets) * 100
udp_ratio = (udp_count / total_packets) * 100

print(f"TCP: {tcp_ratio:.2f}%\nUDP: {udp_ratio:.2f}%")

print("==================================================")
# IP:

ipv4_count = len(filtered_packets["IPv4"])
ipv6_count = len(filtered_packets["IPv6"])

total_packets = ipv4_count + ipv6_count

ipv4_ratio = (ipv4_count / total_packets) * 100
ipv6_ratio = (ipv6_count / total_packets) * 100

print(f"IPv4: {ipv4_ratio:.2f}%\nIPv6: {ipv6_ratio:.2f}%")

print("* IP stats:")
unique_src_ipv4 = {pkt[IP].src for pkt in filtered_packets["IPv4"]}
unique_dst_ipv4 = {pkt[IP].dst for pkt in filtered_packets["IPv4"]}
print(f"Unique IPv4 source addresses: {len(unique_src_ipv4)}")
print(f"Unique IPv4 destination addresses: {len(unique_dst_ipv4)}")

unique_src_ipv6 = {pkt[IPv6].src for pkt in filtered_packets["IPv6"]}
unique_dst_ipv6 = {pkt[IPv6].dst for pkt in filtered_packets["IPv6"]}
print(f"Unique IPv6 source addresses: {len(unique_src_ipv6)}")
print(f"Unique IPv6 destination addresses: {len(unique_dst_ipv6)}")

print("==================================================")
# HTTP:
print("* HTTP stats:")
http_packets = [pkt for pkt in filtered_packets["TCP"] if pkt[TCP].dport == 80 or pkt[TCP].dport == 80]
https_packets = [pkt for pkt in filtered_packets["TCP"] if pkt[TCP].dport == 443 or pkt[TCP].dport == 443]
print(f"Number of HTTP packets: {len(http_packets)}")
print(f"|-> Showing first 5 HTTP traffic entries:")
for pkt in http_packets[:5]:  
    print(f"HTTP traffic between {pkt[IP].src}:{pkt[TCP].sport} and {pkt[IP].dst}:{pkt[TCP].dport}")
print(f"|-> Showing first 5 HTTPS traffic entries:")
print(f"Number of HTTPS packets: {len(https_packets)}")
for pkt in https_packets[:5]:  
    print(f"HTTPS traffic between {pkt[IP].src}:{pkt[TCP].sport} and {pkt[IP].dst}:{pkt[TCP].dport}")

print("==================================================")
# DNS:
print("* DNS stats:")
dns_queries = [pkt for pkt in filtered_packets["DNS"] if pkt[DNS].qr == 0]
dns_replies = [pkt for pkt in filtered_packets["DNS"] if pkt[DNS].qr == 1]

unique_dns_queries = {pkt["DNS"].qd.qname.decode() for pkt in dns_queries}
print(f"Number of DNS queries: {len(dns_queries)}")
print(f"Number of unique domains queried: {len(unique_dns_queries)}")
print(f"|-> Showing first 10 entries:")
for i, domain in enumerate(list(unique_dns_queries)[:10], 1): 
    print(f"-Requested domain {i}: {domain}")

print(f"Number of DNS replies: {len(dns_replies)}")

print("==================================================")
