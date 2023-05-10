import socket,struct
ICMP_CODE = socket.getprotobyname('icmp')

my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
img_dat = open("/tmp/kano.jpg","w+b")

while True:
    rec_packet, addr = my_socket.recvfrom(1024)
    icmp_header = rec_packet[20:]
    if icmp_header[0] == 8: #ICMP pkt only
        icmp_type = struct.unpack('H',icmp_header[0:2])
        icmp_checksum = struct.unpack('H',icmp_header[2:4])
        icmp_ident = struct.unpack('H',icmp_header[4:6])
        if icmp_ident[0] == 2525:
            icmp_seq = struct.unpack('H',icmp_header[6:8])
            print(f"Get payload {icmp_header[8:]}")
            img_dat.write(icmp_header[8:])
            if icmp_seq[0] == 2:
                print("transter file complete")
                break