import struct

def main():
    f = open('dump_file.txt', 'rb')
    i = 1
    for ethernet_frame in f.read().split(b'\n'):
        print('Ethernet frame #', i)
        print('====================')
        i += 1
        if len(ethernet_frame) >= 64: # minimum ethernet frame size
            proto = struct.unpack('! 12x H', ethernet_frame[:14])[0]
            if proto == 0x0800: # ipv4
                ipv4_packet = ethernet_frame[14:-4] # payload starts at byte 15 and ends 4 from the end
                parse_and_print_ipv4(ipv4_packet)
        else:
            print('Incomplete ethernet frame discarded.')
        print('')
    f.close()


def convert_binary_to_hex_string(bin, sep, mark=False):
    start = ''
    if mark:
        start = '0x'
    return start + sep.join(map('{:02x}'.format, bin)).upper()


def convert_binary_to_ip_address(bin):
    return '.'.join(map(str, bin))


def parse_and_print_ipv4(ipv4):
    version, hl, tos, tl, id, flags, fo, ttl, proto, hc, src, dest, opt, data = parse_ipv4(ipv4)
    print('IPV4')
    print('')
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
    print('Source address:', convert_binary_to_ip_address(src))
    print('Destination address:', convert_binary_to_ip_address(dest))
    print('Options:', convert_binary_to_hex_string(opt, ' '))
    print('Data:', convert_binary_to_hex_string(data, ' '))
    print('')

    if proto == 6:
        parse_and_print_tcp(data)
    elif proto == 17:
        parse_and_print_udp(data)


def parse_and_print_tcp(tcp):
    src, dest, seq, ack, off, res, flags, win, chk, urg, opt, data = parse_tcp(tcp)
    print('TCP')
    print('')
    print('Source port:', src)
    print('Destination port:', dest)
    print('Sequence number:', seq)
    print('Acknowledgement number:', ack)
    print('Offset:', off)
    print('Reserved:', res)
    print('Flags:', flags)
    print('Window:', win)
    print('Checksum:', convert_binary_to_hex_string(chk, ' '))
    print('Urgent pointer:', urg)
    print('Options:', convert_binary_to_hex_string(opt, ' '))
    print('Data:', convert_binary_to_hex_string(data, ' '))


def parse_and_print_udp(udp):
    src, dest, length, chk, data = parse_udp(udp)
    print('UDP')
    print('')
    print('Source port:', src)
    print('Destination port:', dest)
    print('Length:', length)
    print('Checksum:', convert_binary_to_hex_string(chk, ' '))
    print('Data:', convert_binary_to_hex_string(data, ' '))


def parse_ipv4(ipv4):
    version = ipv4[0] >> 4 # left half of byte
    hl = ipv4[0] & 15 # right half of byte
    flags = ipv4[6] >> 5
    fo = ((ipv4[6] & 31) << 8) | ipv4[7]
    tos, tl, id, ttl, proto, hc, src, dest = struct.unpack('! x B H H 2x B B 2s 4s 4s', ipv4[:20])
    opt = ipv4[20:4 * hl]
    data = ipv4[4 * hl:]
    return version, hl, tos, tl, id, flags, fo, ttl, proto, hc, src, dest, opt, data


def parse_tcp(tcp):
    off = tcp[12] >> 4
    res = tcp[12] & 15
    src, dest, seq, ack, flags, win, chk, urg = struct.unpack('! H H L L x B H 2s H', tcp[:20])
    opt = tcp[20:4 * off]
    data = tcp[4 * off:]
    return src, dest, seq, ack, off, res, flags, win, chk, urg, opt, data

def parse_udp(udp):
    src, dest, length, chk = struct.unpack('! H H H 2s', udp[:8])
    data = udp[8:]
    return src, dest, length, chk, data

if __name__ == '__main__':
    main()
