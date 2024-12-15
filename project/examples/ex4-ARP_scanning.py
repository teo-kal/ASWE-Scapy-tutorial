from scapy.all import ARP, Ether, srp

network_address = input("Insert the network IP address (format: A.B.C.D): ").strip()
subnet = input("Insert the subnet mask value: (format: number): ").strip()
target = f"{network_address}/{subnet}"

# Creating the ARP request
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)

print(f"Scanning {target} network...")

answered, unanswered = srp(packet, timeout=2, verbose=False)

print("Active (W)LAN users:")
for sent, received in answered:
    print(f"IP: {received.psrc}, MAC: {received.hwsrc}")