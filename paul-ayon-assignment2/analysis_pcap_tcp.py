import dpkt
import socket

sender = '130.245.145.12'
receiver = '128.208.2.198'


def get_ip(ip):
    return socket.inet_ntop(socket.AF_INET, ip)  # Can assume sender & receiver are IP4 addrs

def compare_packets(packet1, packet2):
    return packet1.data.seq == packet2.data.seq and packet1.data.ack == packet2.data.ack

def compare_sender_receiver(sender_transactions, tcp):
    for transaction in sender_transactions:
        if transaction.seq < tcp.ack:
            return True
    return False

def analysis_pcap_tcp(file):
    ############### PART 1 ###############
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

            if get_ip(ip_packet.src) != sender:
                flow_key = f'({tcp_segment.dport}, {get_ip(ip_packet.dst)}, {tcp_segment.sport}, {get_ip(ip_packet.src)})'

            # Add this TCP packet to said TCP flow if it hasn't been already
            if flow_key not in flows:
                flows[flow_key] = [ip_packet]
                continue

            flows[flow_key].append(ip_packet)

    print(f'Number of flows: {len(flows)}\n')

    for index, flow in enumerate(flows):
        print(f'Flow #{index + 1}: {flow}')

        total_bytes = 0
        transactions = [[], []]

        for p_index, packet in enumerate(flows[flow]):
            ip = get_ip(packet.src)
            tcp_segment = packet.data

            if tcp_segment.flags & dpkt.tcp.TH_FIN:
                break

            # Skip connection establishment and duplicates
            if tcp_segment.flags & dpkt.tcp.TH_SYN or compare_packets(packet, flows[flow][p_index-1]):
                continue

            #Add to throughput if connection is in progress and packet from sender
            total_bytes += len(tcp_segment) if ip == sender else 0

            # Print out first 2 transactions (total of 4 prints)
            # if (get_ip(packet.src) == sender and len(transactions) < 4) or (get_ip(packet.src) == receiver and compare_packets(packet, transactions[len(transactions)-1])):
            if len(transactions[0]) < 2 and ip == sender and len(tcp_segment.data) != 0:
                transactions[0].append(tcp_segment)
                print(f'flow {index + 1}: Sender -> Receiver | Transaction {len(transactions[0])} Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

            if len(transactions[1]) < 2 and compare_sender_receiver(transactions[0], tcp_segment):
                transactions[1].append(tcp_segment)
                print(f'flow {index + 1}: Receiver -> Sender | Transaction {len(transactions[1])} Sequence #: {tcp_segment.seq} Ack #: {tcp_segment.ack} Received Window Size: {tcp_segment.win}')

        print(f'Throughput: {total_bytes} bytes\n')

    ############### PART 2 ###############
    ##TODO
    f.close()

analysis_pcap_tcp('assignment2.pcap')