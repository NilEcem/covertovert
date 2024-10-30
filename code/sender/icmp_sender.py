# Implement your ICMP sender here
from scapy.all import IP, ICMP, send

def send_icmp():
    dest_ip = "receiver"
    packet = IP(dst=dest_ip, ttl=1)/ICMP()
    send(packet)

if __name__ == "__main__":
    send_icmp()
