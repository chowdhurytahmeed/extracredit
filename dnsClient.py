#Tahmeed Chowdhury

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
    qname_parts = name.split('.') 
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('ascii') for part in qname_parts]  
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00' 

    if type == 'A':
        qtype = 1 
    elif type == 'AAAA':
        qtype = 28  
    else:
        raise ValueError('Invalid')

    qclass = 1  
    question = qname_encoded + struct.pack('!HH', qtype, qclass)
    message = header + question 
    sent = sock.sendto(message, server_address)
    data, _ = sock.recvfrom(4096) 

    response_header = data[:12]  
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    response_question = data[12:12+len(question)]
    assert response_question == question

    response_answer = data[12+len(question):]  
    offset = 0
    for _ in range(ANCOUNT):
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                pointer = struct.unpack('!H', response_answer[offset-1:offset+1])[0] & 0x3fff
                offset += 1
                name_parts.append(parse_name(data, pointer))
                break
            else:
                label = response_answer[offset:offset+length].decode('ascii') 
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset+10]) 
        offset += 10 

        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if type == 1:  # Value for A record
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
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

