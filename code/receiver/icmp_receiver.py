# Implement your ICMP receiver here

from scapy.all import sniff, IP, ICMP

def handle_packet(packet):
    if IP in packet and ICMP in packet and packet[IP].ttl == 1 and packet[ICMP].type == 8:
        packet.show()

def receive_icmp():
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    receive_icmp()
