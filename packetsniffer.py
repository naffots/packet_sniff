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

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def ip_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x" % (int(a[0],16) , int(a[1],16) , int(a[2],16) , int(a[3]),16)
    return b

def parse_udp(header, data):
    udph = unpack('!HHHH' , header)

    source_port = udph[0]
    dest_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    print "Source port: ", source_port
    print "Destination port: ", dest_port

    if (dest_port==2068):
      frame_n=ord(data[0])*256+ord(data[1])
      part=ord(data[3])
      print "frame",frame_n,"part",part, "len",len(data),"end?",end
      if (part==0) & notopen:
         f = open('files/'+str(frame_n)+"_"+str(part).zfill(3)+'.jpg', 'w')
         notopen=0
      if notopen==0:
          f.write(data[4:])

def parse_tcp(data):
    # Parse first part of header
    tcp_header_start = data[0:16]
    tcph = unpack('!HHIIBBH', tcp_header_start)
    source_port = tcph[0]
    dest_port = tcph[1]
    seq_nr = tcph[2]
    ack_nr = tcph[3]
    options = 0x3F & tcph[5]
    syn_bit = 0x2 & options
    ack_bit = 0x16 & options
    window_size = tcph[6]

    # The number of 32 bit words in header
    data_offset_temp = tcph[4]
    data_offset = data_offset_temp >> 4

    # Parse last part of header
    tcp_header_length = data_offset * 4
    tcp_header_end = data[16:tcp_header_length]
    tcp_data = data[tcp_header_length:]

    #print "Source port: ", source_port
    #print "Destination port: ", dest_port
    #print "Seq: ", seq_nr
    #print "Next seq nr: ", seq_nr + data_offset
    #print "Ack: ", ack_nr
    #print "SYN_ON" if syn_bit else "SYN_OFF"
    #print "ACK_ON" if ack_bit else "ACK_ON"
    #print "Data offset: ", data_offset

    return tcp_data


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

#parse ethernet heade
eth_length = 14


# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    # Parse header
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)

    eth_protocol = socket.ntohs(eth[2])

    #print "---------------------------------------------"
    #print "Sender: ",eth_addr(eth[1])
    #print "Destination: ",eth_addr(eth[0])
    #print "Type: ",eth_protocol

    # IP protocol = 8
    if (eth_protocol == 8) :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:eth_length+20]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        #print "IP length: ", iph_length

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        #print "IP Sender: ", s_addr
        #print "IP Destination: ", d_addr
        #print "PROTOCOL: ", protocol

        u = iph_length + eth_length
        # UDP packet
        if protocol == 17 :
            udph_length = 8
            udp_header = packet[u:u+udph_length]
            udp_data = packet[u+udph_length+1:]
            parse_udp(udp_header, udp_data)
        # TCP packet
        elif protocol == 6:
            tcp_data = parse_tcp(packet[u:])

            if s_addr == "80.217.210.121":
                 f = open('paket.jpg', 'a')
                 f.write(bytearray(tcp_data))
                 f.close()
