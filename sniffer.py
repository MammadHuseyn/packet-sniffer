import socket
import struct
import textwrap

# to unpack the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, len = struct('! 6s 6s H', data[:14]) # ! is for the big, little endian
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(len), data[14:]


def get_mac_add(bytes_add):
    bytes_str = map("{02x}".format, bytes_add) #formatting all chunks into 2decimal places
    mac_add = ":".join(bytes_str).upper()
    return mac_add
    