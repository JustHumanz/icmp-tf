import socket,ipaddress,struct,time

ICMP_MAX_DATA_LEN = 512

def checksum(data):
    """Creates the ICMP checksum as in RFC 1071
    :param data: Data to calculate the checksum ofs
    :type data: bytes
    :return: Calculated checksum
    :rtype: int
    Divides the data in 16-bits chunks, then make their 1's complement sum"""
    subtotal = 0
    for i in range(0, len(data)-1, 2):
        subtotal += ((data[i] << 8) + data[i+1])                # Sum 16 bits chunks together
    if len(data) % 2:                                           # If length is odd
        subtotal += (data[len(data)-1] << 8)                    # Sum the last byte plus one empty byte of padding
    while subtotal >> 16:                                       # Add carry on the right until fits in 16 bits
        subtotal = (subtotal & 0xFFFF) + (subtotal >> 16)
    check = ~subtotal                                           # Performs the one complement
    return ((check << 8) & 0xFF00) | ((check >> 8) & 0x00FF)    # Swap bytes

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

host_ip = ipaddress.IPv4Address('127.0.0.1').packed
dst_ip = ipaddress.IPv4Address('127.0.0.1').packed

ip_header = b'\x45\x00\x00\x1c'     # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'    # Identification | Flags, Fragment Offset
ip_header += b'\x40\x01\x6b\xd8'    # TTL, Protocol | Header Checksum
ip_header += host_ip                # Source Address
ip_header += dst_ip                 # Destination Address

f = open("kano.jpg")
dat_img = f.buffer.read()
dat_img_len = int(len(dat_img)) - 1

icmp_type = struct.pack('<H',8)                 # Protocol type
icmp_identifier = struct.pack('<H',2525)        # Icmp identifier
mod = dat_img_len % ICMP_MAX_DATA_LEN
if mod != 0:
    dat_img_len + mod
    for i in range(0,mod):
        dat_img += struct.pack('<H',0)

for i in range(0,dat_img_len,ICMP_MAX_DATA_LEN):
    end = i+ICMP_MAX_DATA_LEN
    payload = dat_img[i:end]
    icmp_seq = struct.pack('<H',i)              # Icmp sequence
    if end >= dat_img_len:
        icmp_seq = struct.pack('<H',2)
    icmp_checksum = struct.pack('<H',checksum(icmp_type+icmp_identifier+icmp_seq+payload))
    print(f"Send payload {payload} len payload {len(payload)}")
    packet = ip_header + icmp_type+icmp_checksum+icmp_identifier+icmp_seq+payload
    s.sendto(packet, ('192.168.122.181', 0))
    time.sleep(1)