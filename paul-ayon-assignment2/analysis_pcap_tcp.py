import dpkt
import socket
from dpkt.compat import compat_ord

sender = '130.245.145.12'
receiver = '128.208.2.198'

def get_ip(ip):
    return socket.inet_ntop(socket.AF_INET, ip) #Can assume sender & receiver are IP4 addrs

def analysis_pcap_tcp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    flows = dict()

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip_packet = eth.data

        if get_ip(ip_packet.src) != sender:
            continue #Disregard flows where src port is not sender

        #If the data portion of the ip packet is a TCP segment, parse the TCP segment
        if isinstance(ip_packet.data, dpkt.tcp.TCP):  
            tcp_segment = ip_packet.data

            flow_key = f'({tcp_segment.sport}, {get_ip(ip_packet.src)}, {tcp_segment.dport}, {get_ip(ip_packet.dst)})'
    
            #TCP flow is identified by the src dst tuple
            #Add this TCP packet to said TCP flow
            if flow_key not in flows:
                flows[flow_key] = [ip_packet]
                continue
            
            flows[flow_key].append(ip_packet)
    
    print(f'Number of flows: {len(flows)}')   

    for index, flow in enumerate(flows): 
        print(f'Flow #{index+1}: {flow}')
        flows[flow].sort(key=lambda packet: packet.data.seq) #Make sure the packets are in order by seq #
        
        for p_index, packets in enumerate(flows[flow]):
            tcp_segment = packets.data

            sync = tcp_segment.flags & dpkt.tcp.TH_SYN
            ack = tcp_segment.flags & dpkt.tcp.TH_ACK

            if sync or p_index < 2:
                continue #Ignore sync and synack transactions
                
            print(f'flow {index+1} | Transaction {p_index-1}: Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

    f.close()

analysis_pcap_tcp('assignment2.pcap')