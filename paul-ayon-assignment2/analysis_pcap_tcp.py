import dpkt
import socket

sender = '130.245.145.12'
receiver = '128.208.2.198'

def get_ip(ip):
    return socket.inet_ntop(socket.AF_INET, ip)  # Can assume sender & receiver are IP4 addrs

#Helper function used to find transactions
def compare_sender_receiver(sender_transactions, tcp):
    for transaction in sender_transactions:
        if transaction.seq < tcp.ack:
            return True
    return False

def analysis_pcap_tcp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    flows = dict()

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip_packet = eth.data

        # If the data portion of the ip packet is a TCP segment, parse the TCP segment
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_segment = ip_packet.data

            flow_key = f'({tcp_segment.sport}, {get_ip(ip_packet.src)}, {tcp_segment.dport}, {get_ip(ip_packet.dst)})'
            flow_packet = dict(packet=ip_packet, timestamp=timestamp)

            if get_ip(ip_packet.src) != sender:
                flow_key = f'({tcp_segment.dport}, {get_ip(ip_packet.dst)}, {tcp_segment.sport}, {get_ip(ip_packet.src)})'

            # Add this TCP packet to said TCP flow if it hasn't been already
            if flow_key not in flows:
                flows[flow_key] = [flow_packet]
                continue

            flows[flow_key].append(flow_packet)

    print(f'Number of flows: {len(flows)}\n')

    for index, flow in enumerate(flows):
        print(f'Flow #{index + 1}: {flow}\n')

        total_bytes = 0
        transactions = [[], []]
        rtt = flows[flow][0]["timestamp"]
        start_of_window = 0
        congestion_windows = []
        sender_packets = dict()
        ack_trios = [] #Used for storing the last 3 receiver acks seen for triple duplicate ack
        triple_duplicate_acks_transmitted = 0
        timeout_retransmissions = 0
        other_transmissions = 0

        for p_index, p in enumerate(flows[flow]):
            ip = get_ip(p["packet"].src)
            tcp_segment = p["packet"].data
            timestamp = p["timestamp"]

            if tcp_segment.flags & dpkt.tcp.TH_FIN:
                break

            if p_index == 1:
                rtt = timestamp - rtt #Using the synack as estimation for 1 RTT

                #Initialize the very first congestion window at the timestamp of the SYNACK, but don't count SYNACK packet
                start_of_window = timestamp
                congestion_windows.append(0)
            
            #Consider all receiver packets when storing the last 3 receiver acks seen
            if ip == receiver:
                ack_trios.append(tcp_segment.ack)
                ack_trios = ack_trios[1:4] if len(ack_trios) > 3 else ack_trios

            # Skip connection establishment
            if tcp_segment.flags & dpkt.tcp.TH_SYN:
                continue

            if ip == sender:
                total_bytes += len(tcp_segment) #Add to throughput if packet from sender

                #Only consider transactions where sender has a payload, for a total of 2 transactions
                if len(transactions[0]) < 2 and len(tcp_segment.data) != 0:
                    transactions[0].append(tcp_segment)
                    print(f'flow {index + 1}: Sender -> Receiver | Transaction {len(transactions[0])} Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

                #Check for retransmission
                if tcp_segment.seq in sender_packets:
                    #If last 3 receiver acks seen are identical, then retransmission from triple dup ack
                    if len(ack_trios) == 3 and len(set(ack_trios)) == 1:
                        triple_duplicate_acks_transmitted += 1 
                    
                    #Check if transmitted after timeout (2 RTT')
                    elif timestamp - sender_packets[tcp_segment.seq] >= 2 * rtt:
                        timeout_retransmissions+=1
                        
                    else:
                        other_transmissions+=1

                sender_packets[tcp_segment.seq] = timestamp
            
            if ip == receiver:
                #Only consider the first 2 receiver packets that match sender packets
                if len(transactions[1]) < 2 and compare_sender_receiver(transactions[0], tcp_segment):
                    transactions[1].append(tcp_segment)
                    print(f'flow {index + 1}: Receiver -> Sender | Transaction {len(transactions[1])} Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

            #Find the first 3 congestion window sizes
            if len(congestion_windows) < 4:
                #If timestamp falls within this window (ie, 1 RTT from the start of window), add it
                #Else, create new window
                if timestamp <= start_of_window + rtt:
                    congestion_windows[-1]+=1
                    continue

                start_of_window = timestamp
                congestion_windows.append(1)

        print(f'\nThroughput: {total_bytes} bytes')
        print(f'Total RTT: {rtt*1000:.2f} ms')
        print(f'Congestion Window Sizes: {congestion_windows[0:3]}')
        print(f'Total retransmissions: {triple_duplicate_acks_transmitted + timeout_retransmissions}')
        print(f'    Retransmissions due to Triple Duplicate Acks: {triple_duplicate_acks_transmitted}') 
        print(f'    Retransmissions due to timeout: {timeout_retransmissions}')
        print(f'Retransmissions due to other reasons: {other_transmissions}\n')

    f.close()

analysis_pcap_tcp('assignment2.pcap')