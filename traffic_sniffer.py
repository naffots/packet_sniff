#!/usr/bin/python

#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)
#modified by danman
import socket, sys
from struct import *
import struct

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#sock.bind(('', 2068))
# wrong: mreq = struct.pack("sl", socket.inet_aton("224.51.105.104"), socket.INADDR_ANY)
#mreq = struct.pack("=4sl", socket.inet_aton("226.2.2.2"), socket.INADDR_ANY)
#sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

sender="000b78006001".decode("hex")
notopen=1
# = open('/tmp/fifo', 'w')


# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # IP packet 8
    if (eth_protocol == 8) :

        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them, 8 8 16 16 16 8 8 16 32 32
        # Bytes: 1 1 2 2 2 1 1 2 4 4
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        # iph[0] Version | IHL (4,4)
        # iph[1] DSCP | ECN (6,2)
        # iph[2] Total length (16)
        # iph[3] Identification (16)
        # iph[4] Flags | Fragment offset (3,13)
        # iph[5] Time to live (8)
        # iph[6] Protocol (8)
        # iph[7] Checksum (16)
        # iph[8] Source Addr (32)
        # iph[9] Destination Addr (32)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        total_length = iph[2]
        iph_length = ihl * 4

        ttl = iph[5]

        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        #UDP packets
        if (s_addr == "192.168.1.70") & (protocol == 6) :
            identification = iph[3]
            offset = (iph[4] & 0x1FFF) 

            u = iph_length + eth_length
            tcph_length = 32 
            tcp_header = packet[u:u+tcph_length]

            #now unpack them :)
            tcph = unpack('!HHIIBBHHH12s' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence_nr = tcph[2]
            ack_nr = tcph[3]

            #get data from the packet
            h_size = eth_length + iph_length + tcph_length
            data = packet[h_size:]

            f = open('paket.jpg', 'a')
            f.write(bytearray(data))
            f.close()
