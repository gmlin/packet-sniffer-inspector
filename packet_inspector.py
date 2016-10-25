import struct, binascii, codecs, sys

def parse():
    f = open('dump_file.txt', 'rb')
    sys.stdout = open('parsed_file.txt', 'w')
    i = 1
    for ethernet_frame in f.read().split(b'\t\x00\n\x00\n\t'):
        print('Ethernet frame #', i)
        print('====================')
        i += 1
        if len(ethernet_frame) >= 64: # minimum ethernet frame size
            proto = struct.unpack('! 12x H', ethernet_frame[:14])[0]
            if proto == 0x0800: # ipv4
                ipv4_packet = ethernet_frame[14:] # payload starts at byte 15
                parse_and_print_ipv4(ipv4_packet)
        else:
            print('Incomplete ethernet frame discarded.')
        print('')
    f.close()
    sys.stdout.close()
    sys.__stdout__


def convert_bytes_to_hex_string(b, sep='', mark=False):
    start = ''
    if mark:
        start = '0x'
    return start + sep.join(map('{:02x}'.format, b)).upper()

def convert_hex_to_ascii(s):
    #print(s)
    #decode_hex = codecs.getdecoder("hex_codec")
    #string = decode_hex(s)[0]
    
    string = bytes.fromhex(s).decode('ISO-8859-2',"replace")
    #print(hello)
    #print(string)
    #string = ""
#    string = binascii.unhexlify(s)

    #for byte in s:
        #string + str(binascii.b2a_uu(byte))
    #string = binascii.b2a_uu(s)
    return string

def convert_bytes_to_ip_address(b):
    return '.'.join(map(str, b))

def convert_bytes_to_address(b):
    b = b[1:]
    for i in range(len(b)):
        if b[i] >> 4 == 0:
            b = b[:i] + b'.' + b[i + 1:]
    return ''.join(map(chr, b))

def parse_and_print_ipv4(ipv4):
    version, hl, tos, tl, id, flags, fo, ttl, proto, hc, src, dest, opt, data = parse_ipv4(ipv4)
    print('----IPv4----')
    print('Version:', version)
    print('Header length:', hl)
    print('Type of service:', tos)
    print('Total length:', tl)
    print('Identification:', id)
    print('Flags:', flags)
    print('Fragment offset:', fo)
    print('TTL:', ttl)
    print('Protocol:', proto)
    print('Header checksum:', convert_bytes_to_hex_string(hc))
    print('Source address:', convert_bytes_to_ip_address(src))
    print('Destination address:', convert_bytes_to_ip_address(dest))
    print('Options:', convert_bytes_to_hex_string(opt))
    print('Data:', convert_hex_to_ascii(data))
    print('')

    if proto == 6:
        parse_and_print_tcp(data)
    elif proto == 17:
        parse_and_print_udp(data)


def parse_and_print_tcp(tcp):
    src, dest, seq, ack, off, res, flags, win, chk, urg, opt, data = parse_tcp(tcp)
    print('----TCP----')
    print('Source port:', src)
    print('Destination port:', dest)
    print('Sequence number:', seq)
    print('Acknowledgement number:', ack)
    print('Offset:', off)
    print('Reserved:', res)
    print('Flags:', flags)
    print('Window:', win)
    print('Checksum:', convert_bytes_to_hex_string(chk))
    print('Urgent pointer:', urg)
    print('Options:', convert_bytes_to_hex_string(opt))
    print('Data:', convert_bytes_to_hex_string(data))

    if src == 53 or dest == 53:
        parse_and_print_dns(data)
    elif src == 80 or src == 443:
        parse_and_print_http_response(data)
    elif dest == 80 or dest == 443:
        parse_and_print_http_request(data)


def parse_and_print_http_request(http):
    return

def parse_and_print_http_response(http):
    return

def parse_and_print_udp(udp):
    src, dest, length, chk, data = parse_udp(udp)
    print('----UDP----')
    print('Source port:', src)
    print('Destination port:', dest)
    print('Length:', length)
    print('Checksum:', convert_bytes_to_hex_string(chk))
    print('Data:', convert_bytes_to_hex_string(data))

    if src == 53 or dest == 53:
        parse_and_print_dns(data)


def parse_and_print_dns(dns):
    id, qr, op, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount, qname, qtype, qclass, ans_name, \
    ans_type,  ans_class, ans_ttl, ans_rdlength, ans_rdata,  auth_name, auth_type, auth_class, auth_ttl, \
    auth_rdlength, auth_rdata, add_name, add_type, add_class, add_ttl, add_rdlength, add_rdata = parse_dns(dns)

    print('----DNS----')
    print('Header')
    print('ID:', id)
    print('QR:', qr)
    print('Opcode:', op)
    print('AA:', aa)
    print('TC:', tc)
    print('RD:', rd)
    print('RA:', ra)
    print('Z:', z)
    print('RCODE:', rcode)
    print('QDCOUNT:', qdcount)
    print('ANCOUNT:', ancount)
    print('NSCOUNT:', nscount)
    print('ARCOUNT:', arcount)
    for i in range(len(qname)):
        print('')
        print('Question')
        print('QNAME:', convert_bytes_to_address(qname[i]))
        print('QTYPE:', convert_bytes_to_hex_string(qtype[i]))
        print('QCLASS:', convert_bytes_to_hex_string(qclass[i]))
    for i in range(len(ans_name)):
        print('')
        print('Answer')
        print('NAME:', convert_bytes_to_address(ans_name[i]))
        print('TYPE:', ans_type[i])
        print('CLASS:', ans_class[i])
        print('TTL:', ans_ttl[i])
        print('RDLENGTH:', ans_rdlength[i])
        print('RDATA:', convert_bytes_to_hex_string(ans_rdata[i]))
    for i in range(len(auth_name)):
        print('')
        print('Authority')
        print('NAME:', convert_bytes_to_address(auth_name[i]))
        print('TYPE:', auth_type[i])
        print('CLASS:', auth_class[i])
        print('TTL:', auth_ttl[i])
        print('RDLENGTH:', auth_rdlength[i])
        print('RDATA:', convert_bytes_to_hex_string(auth_rdata[i]))
    for i in range(len(add_name)):
        print('')
        print('Additional')
        print('NAME:', convert_bytes_to_address(add_name[i]))
        print('TYPE:', add_type[i])
        print('CLASS:', add_class[i])
        print('TTL:', add_ttl[i])
        print('RDLENGTH:', add_rdlength[i])
        print('RDATA:', convert_bytes_to_hex_string(add_rdata[i]))

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

def parse_dns(dns):
    qr = dns[2] >> 7
    op = (dns[2] >> 3) & 7
    aa = (dns[2] >> 2) & 1
    tc = (dns[2] >> 1) & 1
    rd = dns[2] & 63
    ra = dns[3] >> 7
    z = (dns[3] >> 4) & 7
    rcode = dns[3] & 7
    id, qdcount, ancount, nscount, arcount = struct.unpack('! H 2x H H H H', dns[:12])
    dns = dns[12:]

    qname = []
    qtype = []
    qclass = []
    for i in range(qdcount):
        if qr == 1:
            break
        qname.append(b'')
        while dns[:1] != b'\x00':
            qname[-1] += dns[:1]
            dns = dns[1:]
        dns = dns[1:]
        t, c = struct.unpack('! 2s 2s', dns[:4])
        qtype.append(t)
        qclass.append(c)
        dns = dns[4:]

    ans_name = []
    ans_type = []
    ans_class = []
    ans_ttl = []
    ans_rdlength = []
    ans_rdata = []
    for i in range(ancount):
        ans_name.append(b'')
        while dns[:1] != b'\x00':
            ans_name[-1] += dns[:1]
            dns = dns[1:]
        dns = dns[1:]
        t, c, ttl, rdlength = struct.unpack('! H H L H', dns[:10])
        dns = dns[10:]
        ans_type.append(t)
        ans_class.append(c)
        ans_ttl.append(ttl)
        ans_rdlength.append(rdlength)
        ans_rdata.append(dns[:rdlength])
        dns = dns[rdlength:]

    auth_name = []
    auth_type = []
    auth_class = []
    auth_ttl = []
    auth_rdlength = []
    auth_rdata = []
    for i in range(nscount):
        auth_name.append(b'')
        while dns[:1] != b'\x00':
            auth_name[-1] += dns[:1]
            dns = dns[1:]
        dns = dns[1:]
        t, c, ttl, rdlength = struct.unpack('! H H L H', dns[:10])
        dns = dns[10:]
        auth_type.append(t)
        auth_class.append(c)
        auth_ttl.append(ttl)
        auth_rdlength.append(rdlength)
        auth_rdata.append(dns[:rdlength])
        dns = dns[rdlength:]

    add_name = []
    add_type = []
    add_class = []
    add_ttl = []
    add_rdlength = []
    add_rdata = []
    for i in range(arcount):
        add_name.append(b'')
        while dns[:1] != b'\x00':
            add_name[-1] += dns[:1]
            dns = dns[1:]
        dns = dns[1:]
        t, c, ttl, rdlength = struct.unpack('! H H L H', dns[:10])
        dns = dns[10:]
        add_type.append(t)
        add_class.append(c)
        add_ttl.append(ttl)
        add_rdlength.append(rdlength)
        add_rdata.append(dns[:rdlength])
        dns = dns[rdlength:]

    return id, qr, op, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount, qname, qtype, qclass, ans_name, \
    ans_type,  ans_class, ans_ttl, ans_rdlength, ans_rdata,  auth_name, auth_type, auth_class, auth_ttl, \
    auth_rdlength, auth_rdata, add_name, add_type, add_class, add_ttl, add_rdlength, add_rdata