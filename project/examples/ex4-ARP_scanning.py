from scapy.all import ARP, Ether, srp

ip_range = "192.168.0.0/24" # MAKE THIS THE INPUT
network_address = input("Insert the network IP address (format: A.B.C.D): ")
subnet = input("Insert the subnet mask value: (format: number): ")
target = f"{network_address}/{subnet}"

# Creating the ARP request
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

print(f"Scanning {target} network...")

answered, unanswered = srp(packet, timeout=2, verbose=False)

print("Active (W)LAN users:")
for sent, received in answered:
    print(f"IP: {received.psrc}, MAC: {received.hwsrc}")