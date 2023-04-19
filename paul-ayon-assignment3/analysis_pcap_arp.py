from collections import defaultdict
import ipaddress
import struct
import sys
import dpkt

arp_packet_structure = ["Hardware Type", "Protocol Type", "Hardware Size", "Protocol Size",
                        "Opcode", "Sender MAC Address", "Sender IP Address", "Target MAC Address", "Target IP Address"]

def analysis_pcap_arp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    exchanges = defaultdict(list) #Keep track of ARP packet exchanges

    for timestamp, packet in pcap:  
      type = packet[12:14] #Type from byte 13-14 (2 bytes)

      if type.hex() == '0806': #ARP Type is 0x0806
        #MAC addresses being 6 bytes means the 28 bytes after type make up the header
        #Using struct module, MAC addresses must be unpacked as single 6 byte string (6s)
        header = struct.unpack("!HHBBH6sL6sL", packet[14:42])
        header = {element: value for element, value in zip(arp_packet_structure, header)}

        #Make IP addresses more readable
        for element in ["Sender IP Address", "Target IP Address"]:
           header[element] = ipaddress.ip_address(header[element])

        #Make MAC addresses more readable
        for element in ["Sender MAC Address", "Target MAC Address"]: #Make MAC address more readable
           mac = header[element].hex()
           header[element] = ':'.join([mac[i : i + 2] for i in range(0, len(mac), 2)]) 
        
        #Map this packet to the correct exchange
        exchange_key =  f'({header["Sender IP Address"]},{header["Target IP Address"]})'
        reverse_key =  f'({header["Target IP Address"]},{header["Sender IP Address"]})' #Reverse for ARP Replies
        
        #Will either initialize new key value entry, or add to existing and reverse
        #The latter assumes the matching ARP reply was found first
        if header["Opcode"] == 1:
         exchanges[exchange_key].append(header)
         exchanges[exchange_key].reverse()
         
        elif header["Opcode"] == 2:
         exchanges[reverse_key].append(header) #Append ARP reply to either existing or new keyval pair

    complete_exchanges = {k: v for k, v in exchanges.items() if len(v) > 1}

    #Print first exchange that has both request and reply, if such exists
    if len(complete_exchanges) > 0:
      first_exchange = complete_exchanges[list(complete_exchanges)[0]]

      for type, packet in zip(["Request", "Reply"], first_exchange):
        print(f'\n{type}:')
        for key,value in packet.items():
          print(f'\t{key}: {value}')
             
if __name__ == "__main__":
    analysis_pcap_arp(sys.argv[1])