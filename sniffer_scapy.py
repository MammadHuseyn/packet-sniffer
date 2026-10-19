#u gotta install Npcap aswell, to link-layer capture

from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, IPv6
from collections import Counter, defaultdict
#sniff captures packets from a network interface
#ether represents ethernet layer

bytes_by_source = defaultdict(int)
packets_by_source = defaultdict(int)

ether_type_counts = Counter()
protocol_counts = Counter()


def handle_packet(packet):
    if Ether not in packet:
        return

    protocol = ether_type_name(packet[Ether].type)

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

    ip = None
    if IP in packet:
        ip = packet[IP]

    ethernet = packet[Ether]

    source_mac = packet[Ether].src
    packet_size = len(packet)

    packets_by_source[source_mac] += 1
    bytes_by_source[source_mac] += packet_size

    ether_type = packet[Ether].type
    ether_type_counts[ether_type] += 1

    packet_info = (
        f"{datetime.now():%H:%M:%S} "
        f"{ethernet.src} -> {ethernet.dst}"
    )

    if ip is not None:
        packet_info += f" | {ip.src} -> {ip.dst}"

    print(f"{packet_info} | {protocol} | {packet_size} B")

def ether_type_name(ether_type):
    names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
    }

    return names.get(ether_type, "Unknown")


def format_bytes(byte_count):
    units = ("B", "KB", "MB", "GB")
    amount = float(byte_count)

    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024


def print_summary():
    total_packets = sum(packets_by_source.values())
    total_bytes = sum(bytes_by_source.values())

    print("\n\nTraffic summary")
    print("---------------")
    print(f"Total packets: {total_packets}")
    print(f"Total bytes:   {format_bytes(total_bytes)}")

    print("\nDevices by source MAC")
    print("---------------------")
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

    print("\nEtherTypes")
    print("----------")
    print(f"{'Type':<8} {'Name':<14} {'Packets':>10}")
    print("-" * 34)

    for ether_type, count in ether_type_counts.most_common():
        print(
            f"0x{ether_type:04x} "
            f"{ether_type_name(ether_type):<14} "
            f"{count:>10}"
        )

    print("\nProtocols")
    print("---------")
    print(f"{'Protocol':<14} {'Packets':>10}")
    print("-" * 25)

    for protocol, count in protocol_counts.most_common():
        print(f"{protocol:<14} {count:>10}")


try:
    print("Started. Press Ctrl+C.")
    sniff(timeout=10, prn=handle_packet, store=False) #store false, means that we dont keep all packets in memo

finally:
    print_summary()

#Npcap captures the packets at the data-link llayer, 
# and scapy converts them into packet object