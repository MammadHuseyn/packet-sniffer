#u gotta install Npcap aswell, to link-layer capture


from scapy.all import sniff, Ether

#sniff captures packets from a network interface
#ether represents ethernet layer



def handle_packet(packet):
    if Ether in packet: # when packet contains a ethernet layer it runs

        print(f"Destination MAC: {packet[Ether].dst}")
        print(f"Source MAC:      {packet[Ether].src}")
        print(f"Protocol:        {packet[Ether].type:#06x}")

sniff(prn=handle_packet, store=False) #store false, means that we dont keep all packets in memo

#Npcap captures the packets at the data-link llayer, 
# and scapy converts them into packet object