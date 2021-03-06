import sys
import ssl
import time
import os
import select
import threading
import re
import struct
from socket import *
from struct import *
from basic_structures import *

ENDIANNESS = 'big'
GLOBAL_HEADER_B = 24
PACKET_HEADER_B = 16
ETH_HEADER_B = 14
IPV4_HEADER_B = 20
TCP_HEADER_B = 20
TCP_PROTOCOL = 6

connections_list = {}

def main():
    #Read in input
    if(len(sys.argv) < 2):
        print("Missing domain name: python3 TCPReader.py <TCP .cap file>")
        sys.exit(2)

    parse_cap_file()
    print()
    print("----------PART A------------")
    print("Total number of connections: {}".format(len(connections_list)))
    print()

    print("----------PART B------------")
    complete_connections_list = []
    for iteration, conn in enumerate(connections_list.values()):
        print("Connection: {}".format(iteration + 1))
        print("Source Address: {}".format(conn.src_ip))
        print("Destination Address: {}".format(conn.dst_ip))
        print("Source Port: {}".format(conn.src_port))
        print("Destination Port: {}".format(conn.dst_port))
        if(conn.status["R"] > 0):
            print("Status: S{}F{}\R".format(conn.status["S"], conn.status["F"]))
        else:
            print("Status: S{}F{}".format(conn.status["S"], conn.status["F"]))
        if(conn.status["S"] == 0 or conn.status["F"] == 0):
            print("+++++++++++++++++++++++++++++++++++++++++++++++++")
            continue
        print("Start time: {} seconds".format(conn.start_time))
        print("End time: {} seconds".format(conn.end_time))
        print("Duration: {} seconds".format(round(conn.end_time - conn.start_time, 6)))
        print("Number of packets sent from Source to Destination: {} packets".format(conn.num_packets_src_dst))
        print("Number of packets sent from Destination to Source: {} packets".format(conn.num_packets_dst_src))
        print("Total number of packets: {} packets".format(conn.num_packets))
        print("Number of data bytes sent from Source to Destination: {} bytes".format(conn.bytes_src_dst))
        print("Number of data bytes sent from Destination to Source: {} bytes".format(conn.bytes_dst_src))
        print("Total number of data bytes: {} bytes".format(conn.total_bytes))
        print("END")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++")
        complete_connections_list.append(conn)
        

    print("----------PART C------------")
    print("Total number of complete TCP connections: {}".format(count_complete_connections())) #R\d\n\+
    print("Number of reset TCP connections: {}".format(count_reset_connections())) #R[^0\D]
    print("Number of TCP connections that were still open when the trace capture ended: {}".format(count_incomplete_connections())) #R\d\n\+
    print()
    print("----------PART D------------")
    print("Minimum time duration: {} seconds".format(min(durations_list(complete_connections_list))))
    print("Mean time duration: {} seconds".format(mean(durations_list(complete_connections_list), 5)))
    print("Maximum time duration: {} seconds".format(max(durations_list(complete_connections_list))))
    print()
    print("Minimum RTT value: {} seconds".format(min(rtt_list(complete_connections_list))))
    print("Mean RTT value: {} seconds".format(mean(rtt_list(complete_connections_list), 6)))
    print("Maximum RTT value: {} seconds".format(max(rtt_list(complete_connections_list))))
    print()
    print("Minimum number of packets including both send/received: {} packets".format(min(num_packets_list(complete_connections_list))))
    print("Mean number of packets including both send/received: {} packets".format(mean(num_packets_list(complete_connections_list), 0)))
    print("Maximum number of packets including both send/received: {} packets".format(max(num_packets_list(complete_connections_list))))
    print()
    print("Minimum receive window size including both send/received: {} bytes".format(min(win_size_list(complete_connections_list))))
    print("Mean receive window size including both send/received: {} bytes".format(mean(win_size_list(complete_connections_list), 0)))
    print("Maximum receive window size including both send/received: {} bytes".format(max(win_size_list(complete_connections_list))))

# get_four_tuple
#
# Returns a string version of a sorted four tuple of the given packet.
# param packet - the packet to extract a 4 tuple from. 
# return string - comma delimited four tuple of the packet in string version. 
def get_four_tuple(packet):
    four_tuple = []
    four_tuple.append(packet.IP_header.src_ip)
    four_tuple.append(packet.IP_header.dst_ip)
    four_tuple.append(str(packet.TCP_header.src_port))
    four_tuple.append(str(packet.TCP_header.dst_port))
    four_tuple.sort()
    return ",".join(four_tuple)

# count_complete_connections
#
# Count number of complete connections. 
# return num_complete_conn - number of complete connections. 
def count_complete_connections():
    num_complete_conn = 0
    for conn in connections_list.values():
        status = conn.status
        if(status["S"] > 0 and status["F"] > 0):
            num_complete_conn += 1
    return num_complete_conn

# count_reset_connections
#
# Count number of reset connections. 
# return num_reset_conn - number of connections resetted. 
def count_reset_connections():
    num_reset_conn = 0
    for conn in connections_list.values():
        status = conn.status
        if(status["R"] > 0):
            num_reset_conn += 1
    return num_reset_conn

# count_incomplete_connections
#
# Count number of incomplete connections. 
# return num_incompelte_conn - number of incomplete connections. 
def count_incomplete_connections():
    num_incomplete_conn = 0
    for conn in connections_list.values():
        status = conn.status
        if(status["F"] == 0):
            num_incomplete_conn += 1
    return num_incomplete_conn

# mean
#
# Calculates the mean for values in the list.
# param the_list - a list of values. 
# param digits - a integer specifying the digit to round to
# return - the mean value.
def mean(the_list, digits):
    avg = sum(the_list)/len(the_list)
    return round(avg, digits)

# num_packets_list
#
# Creates a list of total packets transferred in each complete tcp connection.
# param complete_connections_list - a list of complete tcp connections.
# return - list of total packets transferred. 
def num_packets_list(complete_connections_list):
    return [conn.num_packets for conn in complete_connections_list]

# durations_list
#
# Creates a list of all complete tcp connection duration times (end time - start time).
# param complete_connections_list - a list of complete tcp connections.
# return - a list of duration times.
def durations_list(complete_connections_list):
    return [(round(conn.end_time - conn.start_time, 6)) for conn in complete_connections_list]

# win_size_list
#
# Creates a list of reciever window sizes for complete tcp connections. 
# param complete_connections_list - a list of complete tcp connections.
# return win_sizes - a list of reciever window sizes.  
def win_size_list(complete_connections_list):
    win_sizes = []
    for conn in complete_connections_list:
        win_sizes.extend([packet.TCP_header.window_size for packet in conn.packets])
    return win_sizes

# rtt_list
#
# Calculates rtt values based on packet pairs (ack, seq+data_bytes).
# Stores the values in a list. 
# param complete_connections_list - a list of complete tcp connections.
# return rtt - a list of all rtt values. 
def rtt_list(complete_connections_list):
    rtt = []
    #DEBUG
    min_rtt = 100
    min_packet = None
    min_packet_rcv = None
    max_rtt = 0
    max_packet = None
    max_packet_rcv = None
    for conn in complete_connections_list:
        orig_ack = conn.packets[0].TCP_header.ack_num
        orig_seq = conn.packets[0].TCP_header.seq_num
        sender_list = [packet for packet in conn.packets if packet.IP_header.src_ip == conn.src_ip]
        responder_list = [packet for packet in conn.packets if packet.IP_header.src_ip == conn.dst_ip]

        for sender_packet in sender_list:
            data_bytes = sender_packet.tcp_payload_len
            expected_ack = sender_packet.TCP_header.seq_num + data_bytes
            syn_count = sender_packet.TCP_header.flags["SYN"]
            fin_count = sender_packet.TCP_header.flags["FIN"]
            
            for response_packet in responder_list:
                if(sender_packet.timestamp > response_packet.timestamp):
                    continue
                if(data_bytes > 0):
                    if(not response_packet.TCP_header.flags["ACK"]):
                        break
                    if(response_packet.TCP_header.ack_num == expected_ack):
                        sender_packet.get_RTT_value(response_packet)
                        rtt.append(sender_packet.RTT_value)
                        #DEBUG
                        if(sender_packet.RTT_value < min_rtt):
                            min_rtt = sender_packet.RTT_value
                            min_packet = sender_packet
                            min_packet_rcv = response_packet
                        if(sender_packet.RTT_value > max_rtt):
                            max_rtt = sender_packet.RTT_value
                            max_packet = sender_packet
                            max_packet_rcv = response_packet
                        break
                if(syn_count):
                    if(not response_packet.TCP_header.flags["SYN"] or not response_packet.TCP_header.flags["ACK"]):
                        break
                    if(response_packet.TCP_header.ack_num == expected_ack + syn_count):
                        sender_packet.get_RTT_value(response_packet)
                        rtt.append(sender_packet.RTT_value)
                        #DEBUG
                        if(sender_packet.RTT_value < min_rtt):
                            min_rtt = sender_packet.RTT_value
                            min_packet = sender_packet
                            min_packet_rcv = response_packet
                        if(sender_packet.RTT_value > max_rtt):
                            max_rtt = sender_packet.RTT_value
                            max_packet = sender_packet
                            max_packet_rcv = response_packet
                        break
                if(fin_count):
                    if(not response_packet.TCP_header.flags["ACK"]):
                        break
                    if(response_packet.TCP_header.ack_num == expected_ack + fin_count):
                        sender_packet.get_RTT_value(response_packet)
                        rtt.append(sender_packet.RTT_value)
                        #DEBUG
                        if(sender_packet.RTT_value < min_rtt):
                            min_rtt = sender_packet.RTT_value
                            min_packet = sender_packet
                            min_packet_rcv = response_packet
                        if(sender_packet.RTT_value > max_rtt):
                            max_rtt = sender_packet.RTT_value
                            max_packet = sender_packet
                            max_packet_rcv = response_packet
                        break
    return rtt

# parse_cap_file
#
# Reads in the cap file and parse bytes into packets. 
# Relevent data elements in packet headers are organized into the respective basic_structures classes.
# Each packet falls under a TCP connection based on the unique 4-tuple.
def parse_cap_file():
    f = open(sys.argv[1], "rb")
    ##############################################
    ################ GLOBAL HEADER ###############
    ##############################################
    magic_number = int.from_bytes(f.read(4), byteorder=ENDIANNESS)
    version_major = int.from_bytes(f.read(2), byteorder=ENDIANNESS)
    version_minor = int.from_bytes(f.read(2), byteorder=ENDIANNESS)
    thiszone = int.from_bytes(f.read(4), byteorder=ENDIANNESS)
    sigfigs = int.from_bytes(f.read(4), byteorder=ENDIANNESS)
    snaplen = int.from_bytes(f.read(4), byteorder=ENDIANNESS)
    network = int.from_bytes(f.read(4), byteorder=ENDIANNESS)

    packet_num = 0
    orig_time = 0
    while True:
        p = packet()
        packet_num += 1
        p.packet_No = packet_num
        ##############################################
        ################ PACKET HEADER ###############
        ##############################################
        packet_header = f.read(PACKET_HEADER_B)
        # Check for EOF
        if(len(packet_header) < PACKET_HEADER_B):
            print("No more packets")
            f.close()
            break
        packet_header_tup = struct.unpack("iiii", packet_header)
        ts_sec = packet_header_tup[0]
        ts_usec = packet_header_tup[1]
        incl_len = packet_header_tup[2]
        orig_len = packet_header_tup[3]
        if(len(connections_list) == 0):
            orig_time = round(ts_sec + ts_usec * 0.000001, 6)
        p.timestamp_set(struct.pack("i", ts_sec), struct.pack("i", ts_usec), orig_time)

        ##############################################
        ############# ETHERNET HEADER ################
        ##############################################
        ether_header = f.read(ETH_HEADER_B)

        ##############################################
        ################ IP HEADER ###################
        ##############################################
        p.IP_header.get_header_len(f.read(1))
        service_type = int.from_bytes(f.read(1), byteorder=ENDIANNESS)
        p.IP_header.get_total_len(f.read(2))

        ##########################EXTRA DATA
        id = int.from_bytes(f.read(2), byteorder=ENDIANNESS)
        flags_frag_offset = bytes(f.read(2))
        time_to_live = int.from_bytes(f.read(1), byteorder=ENDIANNESS)
        protocol = int.from_bytes(f.read(1), byteorder=ENDIANNESS)
        if(protocol != TCP_PROTOCOL):
            continue
        header_checksum = int.from_bytes(f.read(2), byteorder=ENDIANNESS)
        ###########################################

        source_addr = f.read(4)
        dest_addr = f.read(4)
        p.IP_header.get_IP(source_addr, dest_addr)

        # Dump extra ip header bytes
        num_of_extra_ip_bytes = p.IP_header.ip_header_len - IPV4_HEADER_B
        if(num_of_extra_ip_bytes > 0):
            extra_ip_bytes = f.read(num_of_extra_ip_bytes)

        ##############################################
        ################ TCP HEADER ##################
        ##############################################
        p.TCP_header.get_src_port(f.read(2))
        p.TCP_header.get_dst_port(f.read(2))
        p.TCP_header.get_seq_num(f.read(4))
        p.TCP_header.get_ack_num(f.read(4))
        p.TCP_header.get_data_offset(f.read(1))
        p.TCP_header.get_flags(f.read(1))
        p.TCP_header.get_window_size(f.read(1), f.read(1))
        p.TCP_header.checksum = f.read(2)
        p.TCP_header.ugp = f.read(2)
        #Dump extra bytes of the packet
        data_seg = f.read(incl_len - ETH_HEADER_B - p.IP_header.ip_header_len - TCP_HEADER_B)
        p.get_tcp_payload_len(p.IP_header.total_len)   

        if(get_four_tuple(p) in connections_list):
            connections_list[get_four_tuple(p)].add_packet(p)
        else:
            connections_list[get_four_tuple(p)] = Connection(p)  



if __name__ == "__main__":
    main()