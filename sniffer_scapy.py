#u gotta install Npcap aswell, to link-layer capture

from datetime import datetime, timezone
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, IPv6, DNS, DNSQR
import database
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
    #we need an ethernet layer to get MAC addresses and the EtherType
    if Ether not in packet:
        return

    ethernet = packet[Ether]
    ether_type = ethernet.type
    packet_size = len(packet)
    protocol = ether_type_name(ether_type)
    source_port = None
    destination_port = None

    #check the transport and network protocols in the packet
    if TCP in packet:
        transport = packet[TCP]
        protocol = "TCP"
        source_port = transport.sport
        destination_port = transport.dport
        protocol_counts["TCP"] += 1
    elif UDP in packet:
        transport = packet[UDP]
        protocol = "UDP"
        source_port = transport.sport
        destination_port = transport.dport
        protocol_counts["UDP"] += 1
    elif IP in packet:
        protocol_counts["IPv4"] += 1
    elif IPv6 in packet:
        protocol_counts["IPv6"] += 1
    elif ARP in packet:
        protocol_counts["ARP"] += 1

    #get the IP layer if this packet has IPv4 or IPv6
    source_ip = None
    destination_ip = None
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    database.insert_packet(
        {
            "captured_at": datetime.now(timezone.utc),
            "source_mac": ethernet.src,
            "destination_mac": ethernet.dst,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "ether_type": ether_type,
        }
    )

    #add this packet and its size to the source device's totals
    packets_by_source[ethernet.src] += 1
    bytes_by_source[ethernet.src] += packet_size

    #count how many times each ethernet type appears
    ether_type_counts[ether_type] += 1

    for domain, query_type in dns_queries(packet):
        dns_query_counts[domain] += 1
        database.insert_dns_query(
            {
                "captured_at": datetime.now(timezone.utc),
                "domain": domain,
                "query_type": query_type,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }
        )
        print(f"DNS query: {domain} type {query_type}")

    if UDP in packet and DNS in packet:
        transport = packet[UDP]
        dns = packet[DNS]
        if (
            (transport.sport == 53 or transport.dport == 53)
            and dns.qr == 1
        ):
            print(f"DNS response: answers={dns.ancount}")

    #start building the one-line output for this packet
    packet_info = (
        f"{datetime.now():%H:%M:%S} "
        f"{ethernet.src} -> {ethernet.dst}"
    )

    #add IP addresses when the packet has an IP layer
    if source_ip is not None:
        packet_info += f" | {source_ip} -> {destination_ip}"

    #print the packet details while the sniffer is running
    display_protocol = protocol
    if source_port is not None and destination_port is not None:
        display_protocol = f"{protocol}:{source_port}->{destination_port}"
    print(f"{packet_info} | {display_protocol} | {packet_size} B")


#convert a numeric EtherType into a readable name
def ether_type_name(ether_type):
    names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
    }

    return names.get(ether_type, "Unknown")


def dns_queries(packet):
    """Return domain names from UDP DNS query packets on port 53."""
    if UDP not in packet or DNS not in packet:
        return []

    transport = packet[UDP]
    if transport.sport != 53 and transport.dport != 53:
        return []

    dns = packet[DNS]
    if dns.qr != 0 or DNSQR not in packet:
        return []

    queries = []
    questions = dns.qd if isinstance(dns.qd, list) else [dns.qd]
    for query in questions:
        if not isinstance(query, DNSQR):
            continue
        domain = query.qname.decode("utf-8", errors="replace").rstrip(".")
        if domain:
            queries.append((domain, query.qtype))
    return queries


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


def main():
    print("Started. Press Ctrl+C.")
    database.initialize_database()
    try:
        sniff(prn=handle_packet, store=False)
    finally:
        print_summary()


if __name__ == "__main__":
    main()

#Npcap captures the packets at the data-link llayer, 
# and scapy converts them into packet object