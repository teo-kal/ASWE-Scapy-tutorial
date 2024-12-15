from scapy.all import IP, TCP, sr1, send

# EXAMPLE 2: Sending a TCP SYN packet and printing the syn_ack_response
try:
    destination = "www.postman-echo.com"
    # 1. Create a TCP SYN packet to initiate a connection to a web server
    syn_packet = IP(dst=destination) / TCP(dport=443, flags="S", seq=1000)

    # 2. Send the packet and receive the syn_ack_response
    syn_ack_response = sr1(syn_packet, timeout=1)

    if syn_ack_response:
        if "SA" in syn_ack_response[TCP].flags:
            print("(+) SYN-ACK response received successfully")
        else:
            print("(-) Unexpected flags received:", syn_ack_response[TCP].flags)

        # 3. Show the syn_ack_response packet details
        syn_ack_response.show()

        # 4. Extract and display specific fields
        print("IP info:")
        print(syn_ack_response[IP])

        # NOTE 1: The SEQ value is a big, randomly generated number in order to protect against SYN flooding and SYN poisoning attacks
        
        print(f"IP version: {syn_ack_response[IP].version}")
        print(f"Source IP: {syn_ack_response[IP].src}")
        print(f"Destination IP: {syn_ack_response[IP].dst}")
        
        print("--------------------------------------------------------------------------------")
        
        print("TCP info:")
        print(syn_ack_response[TCP])

        print(f"Source port: {syn_ack_response[TCP].sport}")
        print(f"Destination port: {syn_ack_response[TCP].dport}")   # See NOTE 2
        print(f"Flags: {syn_ack_response[TCP].flags}")              # Should show 'SA' (SYN-ACK) if syn_ack_response is correct

        # NOTE 2: Scapy uses port 20 as the source port for TCP communication by default: https://scapy.readthedocs.io/en/latest/introduction.html 

        print("(+) Completing the TCP handshake by sending the final (ACK) packet")
        seq_number = syn_packet[TCP].seq + 1            
        ack_number = syn_ack_response[TCP].seq + 1      # ACK = SEQ + 1
        ack_packet = IP(dst=destination) / TCP(dport=443, flags="A", seq=seq_number, ack=ack_number)

        send(ack_packet)

        print("(+) TCP handshake completed")
    else:
        print("(-) No syn_ack_response received")

    print("(+) Closing the connection by sending a FIN packet")
    fin_packet = IP(dst=destination) / TCP(dport=443, flags="FA", seq=syn_packet[TCP].seq + 1, ack=ack_number)
    fin_response = sr1(fin_packet, timeout=1)

    if fin_response:
        print("(+) FIN-ACK received")
        fin_response.show()

        # Sending the last ACK in order to close the connection gracefully
        final_ack = IP(dst=destination) / TCP(dport=443, flags="A", seq=fin_packet[TCP].seq + 1, ack=fin_response[TCP].seq + 1)
        send(final_ack)

        print("(+) TCP connection closed")
    else: 
        print("(-) No FIN-ACK received. Sending RST packet in order to reset the connection")

        rst_packet = IP(dst=destination) / TCP(dport=443, flags="R", seq=fin_packet[TCP].seq + 1)
        rst_response = sr1(rst_packet, timeout=1)

except Exception as e:
    print(f"(-) An error occurred: {e}")