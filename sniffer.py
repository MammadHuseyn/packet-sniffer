import socket
import struct
import textwrap

# to unpack the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, len = struct('! 6s 6s H', data[:14]) # ! is for the big, little endian
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(len), data[14:]

    