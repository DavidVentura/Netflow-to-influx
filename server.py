#!/usr/bin/env python3
import ipaddress
import requests
import struct

from socket import inet_ntoa, socket, AF_INET, SOCK_DGRAM

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48
INFLUXDB_HOST = "grafana.labs"
INFLUXDB_PORT = 8086
INFLUXDB_DB = "scripts_data"

influx_url = "http://{host}:{port}/write?db={db}".format(
                host=INFLUXDB_HOST,
                port=INFLUXDB_PORT,
                db=INFLUXDB_DB)

NETWORKS = ['192.168.1.0/24',
            '192.168.2.0/24',
            '192.168.10.0/24',
            '192.168.20.0/24',
            '192.168.30.0/24',
            '192.168.40.0/24',
            '192.168.50.0/24',
            '192.168.0.0/16',
            '224.0.0.0/8']

NETWORKS = [ipaddress.ip_network(n) for n in NETWORKS]

def parse_header(header):
    (version, count) = struct.unpack('!HH', header)
    if version != 5:
        print("Not NetFlow v5!")
        return -1, False

    # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
    if count <= 0 or count >= 1000:
        print("Invalid count %s" % count)
        return -1, False

    return count, True

def get_cidr(ip_addr):
    for net in NETWORKS:
        if ipaddress.ip_address(ip_addr) in net:
            return str(net)
    return '0.0.0.0/0'

def parse_message(buf, i):
    nfdata = {}
    base = SIZE_OF_HEADER + (i * SIZE_OF_RECORD)
    data = struct.unpack('!IIIIHH', buf[base+16:base+36])

    nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
    nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
    nfdata['pcount'] = data[0]
    nfdata['bcount'] = data[1]
    # nfdata['stime'] = data[2]
    # nfdata['etime'] = data[3]
    nfdata['sport'] = data[4]
    nfdata['dport'] = data[5]
    nfdata['scidr'] = get_cidr(nfdata['saddr'])
    nfdata['dcidr'] = get_cidr(nfdata['daddr'])

    if buf[base+38] == 6:
        nfdata['protocol'] = 'T'
    elif buf[base+38] == 17:
        nfdata['protocol'] = 'U'
    elif buf[base+38] == 1:
        nfdata['protocol'] = 'I'
    else:
        nfdata['protocol'] = '?'

    return nfdata

def pprint_message(nfdata):
    print("%s:%s %s -> %s:%s %s [%s]" % (nfdata['saddr'],
                                         nfdata['sport'],
                                         nfdata['scidr'],
                                         nfdata['daddr'],
                                         nfdata['dport'],
                                         nfdata['dcidr'],
                                         nfdata['protocol']))


def post_influx(messages):
    query_str = ''
    line = "net_if,saddr={saddr},daddr={daddr},dport={dport},protocol={protocol},dcidr={dcidr},scidr={scidr} value={bcount}"
    lines = []
    for message in messages:
        query_str = line.format(**message)
        lines.append(query_str)
    r = requests.post(influx_url, data="\n".join(lines))


def listen():
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(('0.0.0.0', 2055))

    while True:
        buf, _ = sock.recvfrom(1500)
        count, valid = parse_header(buf[0:4])
        if not valid:
            continue

        i = 0
        messages = []
        while i < count:
            messages.append(parse_message(buf, i))
            i += 1
        yield messages

if __name__ == '__main__':
    for messages in listen():
        post_influx(messages)
