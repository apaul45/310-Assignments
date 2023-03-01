import dpkt
import socket

sender = '130.245.145.12'
receiver = '128.208.2.198'

def get_ip(ip):
    return socket.inet_ntop(socket.AF_INET, ip) #Can assume sender & receiver are IP4 addrs

def analysis_pcap_tcp(file):
    ############### PART 1 ###############
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    flows = dict()

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip_packet = eth.data

        if get_ip(ip_packet.src) != sender:
            continue #Disregard packets sent from receiver FOR NOW....

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
    
    print(f'Number of flows: {len(flows)}\n')   

    for index, flow in enumerate(flows): 
        print(f'Flow #{index+1}: {flow}')
        flows[flow].sort(key=lambda packet: packet.data.seq) #Make packets in order

        total_bytes = 0

        for p_index, packet in enumerate(flows[flow]):
            tcp_segment = packet.data

            sync = tcp_segment.flags & dpkt.tcp.TH_SYN
            ack = tcp_segment.flags & dpkt.tcp.TH_ACK
        
            #Skip connection establishment 
            #2 rather than 3 because synack got disregarded from prev loop
            if p_index < 2:
                continue

            #Only add to throughput if past connection est. and ack (going up to last ack)
            total_bytes += len(tcp_segment.__bytes__()) if ack else 0
            
            if p_index < 4: #Only print the first 2 transactions
                print(f'flow {index+1} | Transaction {p_index-1}: Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

        print(f'Throughput: {total_bytes} bytes\n')
    
    ############### PART 2 ###############
    ##TODO
    f.close()

analysis_pcap_tcp('assignment2.pcap')