import struct

def main():
    f = open('dump_file.txt', 'rb')
    i = 0
    for ethernet_frame in f.read().split(b'\n'):
        if len(ethernet_frame) >= 64: # minimum ethernet frame size
            proto = struct.unpack('! 12x H', ethernet_frame[:14])[0]
            if proto == 0x0800: # ipv4
                ipv4_packet = ethernet_frame[14:-4] # payload starts at byte 15 and ends 4 from the end
                parse_and_print_packets(ipv4_packet)
    f.close()

def convert_binary_to_hex_string(bin, sep):
    return sep.join(map('{:02x}'.format, bin)).upper()

def convert_binary_to_ip_address(bin):
    return '.'.join(map(str, bin))

def parse_and_print_packets(ipv4_packet):
    version, hl, tos, tl, id, flags, fo, ttl, proto, hc, src, dest, data = parse_ipv4(ipv4_packet)
    print('Version:', version)
    print('Header length:', hl)
    print('Type of service:', tos)
    print('Total length:', tl)
    print('Identification:', id)
    print('Flags:', flags)
    print('Fragment offset:', fo)
    print('TTL:', ttl)
    print('Protocol:', proto)
    print('Header checksum:', convert_binary_to_hex_string(hc, ' '))
    print('Source address', convert_binary_to_ip_address(src))
    print('Destination address', convert_binary_to_ip_address(dest))

    if proto == 6:
        print('TCP')
    elif proto == 17:
        print('UDP')
    else:
        print('Data:', convert_binary_to_hex_string(data, ' '))

    print('')

def parse_ipv4(ipv4_packet):
    version = ipv4_packet[0] >> 4 # left half of byte
    hl = ipv4_packet[0] & 15 # right half of byte
    flags = ipv4_packet[6] >> 5
    fo = ((ipv4_packet[6] & 31) << 8) | ipv4_packet[7]
    tos, tl, id, ttl, proto, hc, src, dest = struct.unpack('! x B H H 2x B B 2s 4s 4s', ipv4_packet[:20])
    data = ipv4_packet[4 * hl:]
    return version, hl, tos, tl, id, flags, fo, ttl, proto, hc, src, dest, data

if __name__ == '__main__':
    main()
