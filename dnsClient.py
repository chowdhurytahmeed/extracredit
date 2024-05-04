import argparse
import socket
import struct

def dns_query(type, name, server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, 53)  

    ID = 0x1234
    QR = 0  
    OPCODE = 0 
    AA = 0 
    TC = 0  
    RD = 1  
    RA = 0  
    Z = 0  
    RCODE = 0  
    QDCOUNT = 1 
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    header = struct.pack('!HHHHHH', ID, QR << 15 | OPCODE << 11 | AA << 10 | TC << 9 | RD << 8 | RA << 7 | Z << 4 | RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    qname_parts = name.split('.')  # Split the domain name into its parts
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('utf-8') for part in qname_parts]
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00'  # End of the QNAME

    # Encode the QTYPE and QCLASS
    if type == 'A':
        qtype = 1  # A record type
    elif type == 'AAAA':
        qtype = 28  # AAAA record type
    else:
        raise ValueError('Invalid type')

    qclass = 1  # IN class
    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    message = header + question
    sent = sock.sendto(message, server_address)

    data, _ = sock.recvfrom(4096)

    response_header = data[:12]  
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    question_end = 12 + len(question)
    assert data[12:question_end] == question

    response_answer = data[question_end:]
    offset = 0
    for _ in range(ANCOUNT):
        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset+2:offset+10])
        offset += 10  # Skip to RDATA
        
        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if type == 1: 
            ipv4 = socket.inet_ntoa(rdata)
            print(f'{name} has IPv4 address {ipv4}')
            return ipv4
        elif type == 28:  
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f'{name} has IPv6 address {ipv6}')
            return ipv6                

def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            pointer = struct.unpack('!H', data[offset-1:offset+1])[0] & 0x3fff
            offset += 1
            name_parts.append(parse_name(data, pointer))
            break
        else:
            # Label
            label = data[offset:offset+length].decode('ascii')
            offset += length
            name_parts.append(label)
    return '.'.join(name_parts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send a DNS query and parse the reply.')
    parser.add_argument('--type', choices=['A', 'AAAA'], required=True, help='the type of address requested')
    parser.add_argument('--name', required=True, help='the host name being queried')
    parser.add_argument('--server', required=True, help='the IP address of the DNS server to query')
    args = parser.parse_args()

    result = dns_query(args.type, args.name, args.server)
