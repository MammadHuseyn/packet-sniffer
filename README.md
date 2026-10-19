# Packet Sniffer

A small Windows packet sniffer written in Python. It uses [Scapy](https://scapy.net/)
to capture live traffic and print packet details, DNS activity, and traffic
statistics.

> Use this tool only on networks and devices that you own or are authorized to
> monitor.

## How it works

The capture path is:

```text
Network adapter
      |
      v
Npcap driver
      |
      v
Scapy's sniff()
      |
      v
handle_packet(packet)
```

The program captures packets for 10 seconds. Pressing `Ctrl+C` stops the
capture early. Each packet is passed to `handle_packet()`, which checks its
protocol layers, prints a short description, and updates the statistics used
in the final summary.

An Ethernet frame has an Ethernet header followed by its payload:

```text
+-------------------+-------------------+----------+----------------+
| Destination MAC   | Source MAC        | EtherType | Payload        |
| 6 bytes           | 6 bytes           | 2 bytes   | Network data   |
+-------------------+-------------------+----------+----------------+
```

Npcap is required on Windows because it provides the packet-capture driver
that gives Scapy access to link-layer traffic. The MAC addresses are in this
link-layer Ethernet header; they are not part of the IP header.

## Requirements

- Windows
- Python 3
- [Npcap](https://npcap.com/#download)
- Scapy
- Administrator privileges when opening the capture interface on Windows

## Installation

### 1. Install Npcap

Download and run the official Npcap installer. During installation, enable:

- **Install Npcap in WinPcap API-compatible Mode**
- **Support raw 802.11 traffic** only if you specifically need Wi-Fi monitor-mode
  traffic

Restart Windows if the installer requests it.

### 2. Install Scapy

This repository already contains a `venv` directory. If you want to use it,
activate it first:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install scapy
```

If you are not using the repository virtual environment, install Scapy with:

```powershell
python -m pip install scapy
```

## Running the sniffer

Open **PowerShell as Administrator**, go to the project directory, and run:

```powershell
python .\sniffer_scapy.py
```

Stop the capture with `Ctrl+C`.

Example output:

```text
Started. Press Ctrl+C.
14:32:08 34:12:98:ab:cd:ef -> 11:22:33:44:55:66 | 192.168.1.20 -> 142.250.72.14 | TCP:51522->443 | 66 B
DNS query: example.com type 1
ended


Traffic summary
---------------
Total packets: 120
Total bytes:   14.5 KB
```

The live output includes:

- Capture time
- Source and destination MAC addresses
- IPv4 source and destination addresses when available
- TCP or UDP source and destination ports
- Packet size
- DNS queries and DNS response answer counts

The final summary includes:

- Total packets and bytes
- Packets and bytes grouped by source MAC address
- Ethernet types such as IPv4, IPv6, ARP, and VLAN
- Protocol counts
- The most frequently queried DNS domains

## Checking available interfaces

To check whether Scapy can see the network interfaces exposed by Npcap:

```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

For more detailed interface information:

```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

## Why not use a normal IP socket?

An `AF_INET` raw socket generally exposes IP packets. It does not reliably
provide the original Ethernet header on Windows, so the source and
destination MAC addresses may not be available. Npcap plus Scapy captures at
the link layer where those addresses are present.

## Project files

- `sniffer_scapy.py` - captures packets and prints traffic statistics
- `helpers/EN-ethernet-frame-structure3.jpg` - Ethernet frame structure image
- `README.md` - setup and usage instructions

## Important notes

- Only capture traffic on networks and devices that you own or are authorized
  to monitor.
- The sniffer does not save packets to a capture file because it uses
  `store=False`.
- The current capture duration is 10 seconds.
