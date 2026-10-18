import socket
import struct
import textwrap

def main():
    HOST = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    conn.bind((HOST,0))
    conn.ioctl(socket.SIO_RCVALL , socket.RCVALL_ON) #switching socket into receive-all mode
    #without it recvfrom gets nothing (blocked)

    while True:
        raw_data, addr = conn.recvfrom(65536) #biggest buffer size
        print(raw_data)
        dest_mac, src_mac, proto, data = ethernet_frame(raw_data)
        print("Frame\n")
        #print("Destination {}\nSource {}\nProtocol {}\n".format(dest_mac, src_mac, proto))


# to unpack the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # ! is for the big, little endian
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(proto), data[14:]


def get_mac_add(bytes_add):
    bytes_str = map("{:02x}".format, bytes_add) #formatting all chunks into 2decimal places
    mac_add = ":".join(bytes_str).upper()
    return mac_add

main()