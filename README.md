# Packet Sniffer

A small Windows packet sniffer written in Python. It uses [Scapy](https://scapy.net/)
to capture live traffic and print the source MAC address, destination MAC address,
and EtherType from Ethernet frames.

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
- Administrator privileges when opening the capture interface

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

## Running the sniffer

Open **PowerShell as Administrator**, go to the project directory, and run:

```powershell
python .\sniffer_scapy.py
```

Stop the capture with `Ctrl+C`.

Example output:

```text
Destination MAC: ff:ff:ff:ff:ff:ff
Source MAC:      34:12:98:ab:cd:ef
Protocol:        0x0800
```

## Checking available interfaces

To check whether Scapy can see the network interfaces exposed by Npcap:

```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

For more detailed interface information:

```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

### Why not use a normal IP socket?

An `AF_INET` raw socket generally exposes IP packets. It does not reliably
provide the original Ethernet header on Windows, so the source and
destination MAC addresses may not be available. Npcap plus Scapy captures at
the link layer where those addresses are present.
