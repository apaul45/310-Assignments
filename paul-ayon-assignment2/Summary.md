# Summary of Assignment
The analysis_pcap_tcp program parses and extracts information from a pcap file,
which is then outputted in a manner similar to other programs such as Wireshark.

</br>

# Part A: Flow level information

## Finding the number of flows
Before looking for the first 2 transactions in each flow,
all of the packets (along with their timestamps) in the pcap file are assigned to the flow they are a part of. This results in a dictionary where keys are the tuples describing a flow, the length of which provides the answer to the number of flows. It is also here that all packets that aren't TCP are discarded.

<br/>

## Finding and outputting the first two transactions

Once all of the packets are preprocessed, the list of packets associated with each flow are looped through to find the required information. 

The first 2 transactions are found through skipping over the connection establishment (ie, the initial three way handshake) and looking for the first two packets sent from the sender that have a non-empty payload. The corresponding packets sent from the receiver are then found by matching their ack number with the seq of one of the two sender packets. That is, the ack number of the potential matching packet must be greater than the seq number of the sender's packet.

</br>

## Finding throughput
Throughput is calculated as the total number of bytes transmitted divided by the total time the flow was active. 

The total number of bytes is calculated as the sum of the length of each sender packet's tcp segment. Packets from the three way handshake or connection termination are not a part of this calculation. 

The total time is calculated as the time a connection begins to terminate (when a packet with a FIN flag is first seen) - 
the timestamp of the sender packet associated with the first transaction.

 </br>

# Part B: Congestion Control

## Finding the first 3 congestion window sizes
In order to find the first 3 cwnd sizes, 1 RTT is first estimated as the timestamp of the packet with the SYN and ACK flags set to 1. This RTT is outputted as the **Total RTT** of the flow.

The **start_of_window** variable is then used to store the timestamp of the beginning of the current window being looked at. The **congestion_windows** list then stores and updates the size of each window as they are encountered.

A packet is considered to be a part of the window if its timestamp is within a RTT of the start_of_window. If it is not part of the window, then it timestamp is assigned to start_of_window and a new window begins. All packets from the flow up until a FIN flag is seen are considered in the calculation.

In terms of the increases seen from window to window, this may have been due to the version of TCP used. That is, the slow start phase may have been the reason why the congestion window increased over time as the connection slowly went into the congestion avoidance phase. If not this, then it may be because the router was more busy (congested) early on but was able to speed up once less packets were being sent.

<br/>

## Finding and examining retransmissions

Retransmissions are tracked with the use of a dictionary whose keys are sequence numbers of packets from the sender and values are timestamps of packets. Whenever a packet's sequence number already exists as a key, this signals that the packet was retransmitted.

<br/>

### Packets retransmitted due to Triple Duplicate Ack
To determine if the packet was retransmitted due to triple duplicate ack, a list called **ack_trios** is used to keep track of the last 3 acks seen. If the packet was retransmistted and the 3 acks in ack_trios are equivalent, the packet is considered retransmitted due to triple duplicate ack.

<br/>

### Packets retransmitted due to RTO
To determine if the packet was retransmitted due to timeout, its timestamp is compared to the timestamp stored in the dictionary described above. If its timestamp is greater than or equal to the last timestamp + 2 RTT, then the packet is considered to be retransmitted due to RTO. 

<br/>

Any packets that aren't retransmitted due to these 2 reasons are then considered to be retransmitted due to other reasons.