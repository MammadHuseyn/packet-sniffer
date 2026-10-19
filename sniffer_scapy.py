#u gotta install Npcap aswell, to link-layer capture

from datetime import datetime
from scapy.all import sniff, Ether, IP
from collections import Counter, defaultdict
#sniff captures packets from a network interface
#ether represents ethernet layer

bytes_by_source = defaultdict(int)
packets_by_source = defaultdict(int)



def handle_packet(packet):
    if Ether not in packet:
        return

    ip = None
    if IP in packet:
        ip = packet[IP]

    ethernet = packet[Ether]

    source_mac = packet[Ether].src
    packet_size = len(packet)

    packets_by_source[source_mac] += 1
    bytes_by_source[source_mac] += packet_size
    

    # when packet contains a ethernet layer it runs
    print(
        f"{datetime.now():%Y-%m-%d %H:%M:%S} | "
        f"{ethernet.src} -> {ethernet.dst} | ", end=""
    )
    
    if ip is not None:
        print(f"{ip.src} -> {ip.dst} | ", end="")

    print(
        f"EtherType: 0x{ethernet.type:04x} | "
        f"Size: {len(packet)} bytes"
    )

def print_summary():
    print("\n\nSummary:")

    for mac_address, total_bytes in sorted(
        bytes_by_source.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(
            f"{mac_address}: "
            f"{packets_by_source[mac_address]} packets, "
            f"{total_bytes} bytes"
        )


try:
    print("Started. Press Ctrl+C.")
    sniff(prn=handle_packet, store=False) #store false, means that we dont keep all packets in memo

finally:
    print_summary()
#Npcap captures the packets at the data-link llayer, 
# and scapy converts them into packet object