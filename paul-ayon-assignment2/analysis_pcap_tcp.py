import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

sender = '130.245.145.12'
receiver = '128.208.2.198'

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def get_ip(ip):
    return socket.inet_ntop(socket.AF_INET, ip) #Can assume sender & receiver are IP4 addrs

def analysis_pcap_tcp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap:
        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        ip_packet = eth.data

        #If the data portion of the ip packet is a TCP segment, parse the TCP segment
        if isinstance(eth.data.data, dpkt.tcp.TCP):  
            print(f'Sender: {get_ip(ip_packet.src)} Receiver: {get_ip(ip_packet.dst)}')
            
            tcp_segment = ip_packet.data
            print(f'Sequence Number: {tcp_segment.seq}, Ack Number: {tcp_segment.ack}\n')

    f.close()

analysis_pcap_tcp('assignment2.pcap')