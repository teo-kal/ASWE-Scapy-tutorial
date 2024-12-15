from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf, get_if_hwaddr

# When we send packets and upon receiving a packet, Scapy checks whether the source IP of the packet we received is the same as the one we sent the initial packet to. We want to disable this in cases like DHCP Discover, since the initial packet we send will be a broadcast, so the packet we receive will definitely NOT match that IP address
conf.checkIPaddr = False

# MAC address of current interface
mac_addr = get_if_hwaddr(conf.iface)

# Crafting a DHCP Discover packet
dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /           # DHCP uses port 68 for the clients, and 67 for the server
    BOOTP(chaddr=mac_addr.encode()) /
    DHCP(options=[
        ("message-type", "discover"), 
        ("param_req_list", [1, 3, 6]),  # Request Subnet mask, Router, and DNS
        "end"
        ])
)

print("Sending DHCP Discover packet...")
# We're sending the DHCP Discover packet, and we want to wait for multiple results since there can be multiple DHCP offers from servers in the network
ans, unans = srp(dhcp_discover, multi=True, timeout=10)

print("\nReceived responses:")
for _, packet in ans:   # _ <- the packet we sent; "packet" <- the packet we received from the DHCP server
    if packet.haslayer(BOOTP):
        print("============================================================")
        print(f"Offered IP address: {packet[BOOTP].yiaddr}")
        print(f"DHCP Server IP: {packet[IP].src}")

        dhcp_options = packet[DHCP].options
        print(f"DHCP options: {dhcp_options}")

        options_dict = {key: value for key, *value in dhcp_options if isinstance(key, str)}

        subnet_mask = options_dict.get('subnet_mask')
        router = options_dict.get('router')
        name_server = options_dict.get('name_server')

        print(f"|--> Subnet mask: {''.join(subnet_mask)}")
        print(f"|--> Router IP: {''.join(router)}")
        print(f"|--> Name Servers: {", ".join(name_server)}")
        print("============================================================")