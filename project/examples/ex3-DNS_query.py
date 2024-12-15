from scapy.all import IP, UDP, DNS, DNSQR, sr1, RandShort

query_types = ["A", "MX", "NS", "CNAME", "TXT", "AAAA"]

target = "elfak.ni.ac.rs"
src_port = RandShort()

for qtype in query_types:
    print("==============================================")
    print(f"Checking if there is a DNS entry of type: {qtype}")
    response = sr1(IP(dst="8.8.8.8") / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=target, qtype=qtype)), timeout=2)
    if response and response[DNS].ancount > 0:
        print(f"{qtype} Records:")
        response[DNS].show()
    else:
        print("No results.")