#u gotta install Npcap aswell, to link-layer capture

from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, IPv6, DNS, DNSQR, DNSRR, Raw
#raw is for the payload, to see it raw, but generally not needed
#sniff captures packets from a network interface
#ether represents ethernet layer
#IP, IPv6, TCP, UDP, and ARP represent different network protocols
#DNS and DNSQR are used to find DNS queries and responses

from collections import Counter, defaultdict
#to store stats, defaultdict auto starts missing values at 0
import database




bytes_by_source = defaultdict(int)
packets_by_source = defaultdict(int)
#dictionaries store traffic stats

ether_type_counts = Counter() #ethernet frame types (IPv4, ARP etc.)
protocol_counts = Counter() #protocols (TCP, UDP, IPv6, ARP)
dns_query_counts = Counter() #dns_query counts


#it was used to convert binary data into text preview,
# but not used, since did not get involved with raw data much
# def printable_preview(payload, limit=32):
#     return "".join(
#         chr(byte) if 32 <= byte < 127 else "."
#         for byte in payload[:limit]
#     )


#main processing function
def handle_packet(packet):

    #checking if packet has a DNS layer
    if DNS in packet:
        dns = packet[DNS]
        if dns.qr == 0 and DNSQR in packet: #qr indicates msg type. 0-query, 1-response
            query = packet[DNSQR]
            domain = query.qname.decode(errors="replace").rstrip(".") #decoding bytes into text
            dns_query_counts[domain] += 1
            print(f"DNS query: {domain} type {query.qtype}")
        elif dns.qr == 1:
            print(f"DNS response: answers={dns.ancount}")

    #we need an ethernet layer to get MAC addresses and the EtherType
    if Ether not in packet:
        return

    #get the name of the protocol inside the ethernet frame
    protocol = ether_type_name(packet[Ether].type)

    #check the transport and network protocols in the packet
    if TCP in packet:
        transport = packet[TCP]
        protocol = f"TCP:{transport.sport}->{transport.dport}"
        protocol_counts["TCP"] += 1
    elif UDP in packet:
        transport = packet[UDP]
        protocol = f"UDP:{transport.sport}->{transport.dport}"
        protocol_counts["UDP"] += 1
    elif IP in packet:
        protocol_counts["IPv4"] += 1
    elif IPv6 in packet:
        protocol_counts["IPv6"] += 1
    elif ARP in packet:
        protocol_counts["ARP"] += 1

    #get the IP layer if this packet has IPv4
    ip = None
    if IP in packet:
        ip = packet[IP]

    #get basic ethernet packet information
    ethernet = packet[Ether]
    source_mac = packet[Ether].src
    packet_size = len(packet)

    #add this packet and its size to the source device's totals
    packets_by_source[source_mac] += 1
    bytes_by_source[source_mac] += packet_size

    #count how many times each ethernet type appears
    ether_type = packet[Ether].type
    ether_type_counts[ether_type] += 1

    #start building the one-line output for this packet
    packet_info = (
        f"{datetime.now():%H:%M:%S} "
        f"{ethernet.src} -> {ethernet.dst}"
    )

    #add IP addresses when the packet has an IPv4 layer
    if ip is not None:
        packet_info += f" | {ip.src} -> {ip.dst}"

    #print the packet details while the sniffer is running
    print(f"{packet_info} | {protocol} | {packet_size} B")


#convert a numeric EtherType into a readable name
def ether_type_name(ether_type):
    names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
    }

    return names.get(ether_type, "Unknown")


#convert bytes into B, KB, MB, or GB
def format_bytes(byte_count):
    units = ("B", "KB", "MB", "GB")
    amount = float(byte_count)

    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024


#print all the statistics collected during the capture
def print_summary():
    total_packets = sum(packets_by_source.values())
    total_bytes = sum(bytes_by_source.values())

    print("\n\nTraffic summary")
    print("---------------")
    print(f"Total packets: {total_packets}")
    print(f"Total bytes:   {format_bytes(total_bytes)}")

    #show traffic totals for every source MAC address
    print("\n")
    print(f"{'Source MAC':<20} {'Packets':>10} {'Bytes':>12}")
    print("-" * 46)

    for mac_address, total_bytes in sorted(
        bytes_by_source.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(
            f"{mac_address:<20} "
            f"{packets_by_source[mac_address]:>10} "
            f"{format_bytes(total_bytes):>12}"
        )

    #show the most common ethernet frame types
    print("\n")
    print(f"{'Type':<8} {'Name':<14} {'Packets':>10}")
    print("-" * 34)

    for ether_type, count in ether_type_counts.most_common():
        print(
            f"0x{ether_type:04x} "
            f"{ether_type_name(ether_type):<14} "
            f"{count:>10}"
        )

    #show the most common protocols
    print("\n")
    print(f"{'Protocol':<14} {'Packets':>10}")
    print("-" * 25)

    for protocol, count in protocol_counts.most_common():
        print(f"{protocol:<14} {count:>10}")

    #show the domains that were queried through DNS
    print("\n")
    print(f"{'Domain':<40} {'Queries':>10}")
    print("-" * 52)

    for domain, count in dns_query_counts.most_common():
        print(f"{domain:<40} {count:>10}")


try:
    print("Started. Press Ctrl+C.")
    #capture for 10 seconds and process each packet with handle_packet
    sniff(timeout=10, prn=handle_packet, store=False) #store false, means that we dont keep all packets in memo

finally:
    #print the summary even when the user stops the program with Ctrl+C
    #print("ended")
    print_summary()

#Npcap captures the packets at the data-link llayer, 
# and scapy converts them into packet object