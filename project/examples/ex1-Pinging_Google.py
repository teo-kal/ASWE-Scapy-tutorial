from scapy.all import IP, ICMP, sr, sr1
import socket

# EXAMPLE 1: Creating an ICMP (ping) packet, printing the response and its fields

# 0. Helper function for returning the protocol name using Python's built-in socket lib
def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

# 1. Create a combined packet using IP and ICMP:
packet = IP(dst="www.google.com") / ICMP()

# 2. Send the packet and receive the response:
single_response = sr1(packet, timeout=1)
print(single_response)

answered, unanswered = sr(packet, timeout=1)

print(answered)
for sent, received in answered:
    print("INFO:")
    print(sent)
    print(received)
print("=====")

if single_response:
    # 3. Show the response:
    single_response.show()

    # 4. Show specific fields:
    print("IP info:")
    print(single_response[IP])

    print(f"IP version: {single_response[IP].version}")
                                                
    protocol_number = single_response[IP].proto                # Shows the protocol number: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    protocol_name = proto_name_by_num(protocol_number)  # 1 <-> ICMP
    print(f"Protocol number: {protocol_number}. Protocol name: {protocol_name}")
   
    print(f"Source: {single_response[IP].src}")
    print(f"Destination: {single_response[IP].dst}")
    
    print("--------------------------------------------------------------------------------")

    print("ICMP info:")
    print(single_response[ICMP])
    
    print(f"Type: {single_response[ICMP].type}")
else:
    print("No response received.")

