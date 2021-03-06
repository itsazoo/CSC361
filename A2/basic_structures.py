import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   

class packet():
    
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    tcp_payload_len = 0
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)

    def packet_No_set(self,number):
        self.packet_No = number
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        RTT_flag = True
        self.RTT_value = round(rtt,8)
    
    def get_tcp_payload_len(self, total_len):
        self.tcp_payload_len = total_len - self.IP_header.ip_header_len - self.TCP_header.data_offset

# Connection
#
# This class stores data elements for each connection.
class Connection: 
    num_packets = 0
    num_packets_src_dst = 0
    num_packets_dst_src = 0
    window_size = 0
    total_bytes = 0
    bytes_src_dst = 0
    bytes_dst_src = 0
    start_time = 0
    end_time = 0
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    status = None
    packets = None

    def __init__(self, packet):
        self.src_ip = packet.IP_header.src_ip
        self.dst_ip = packet.IP_header.dst_ip
        self.src_port = packet.TCP_header.src_port
        self.dst_port = packet.TCP_header.dst_port
        self.set_start_time(packet)
        self.status = {
                        "S": 0,
                        "F": 0,
                        "R": 0  
                        }
        self.packets = []
        self.add_packet(packet)
    
    # add_packet
    #
    # Add packet to connection's packet list and update relevant connection stats
    # param packet - the packet to be added to the Connection
    def add_packet(self, packet):
        self.total_bytes += packet.tcp_payload_len
        self.num_packets += 1
        self.update_end_time(packet)
        self.update_conn_stats(packet)
        
        if(packet.IP_header.src_ip == self.src_ip):
            self.num_packets_src_dst += 1
            self.bytes_src_dst += packet.tcp_payload_len
        else:
            self.num_packets_dst_src += 1
            self.bytes_dst_src += packet.tcp_payload_len
        self.packets.append(packet)

    # set_start_time
    #
    # Sets start_time to the timestamp of the first syn packet.
    # ie. timestamp of the first syn packet
    def set_start_time(self, packet):
        if(packet.TCP_header.flags["SYN"]):
            self.start_time = packet.timestamp

    # update_end_time
    #
    # Update end_time of the connection.
    # ie. timestamp of the last FIN packet
    def update_end_time(self, packet):
        if(packet.TCP_header.flags["FIN"]):
            self.end_time = packet.timestamp

    # update_conn_stats
    #
    # Store counts for syn, rst, and fin flags in status dictionary.
    def update_conn_stats(self, packet):
        self.status["S"] += packet.TCP_header.flags["SYN"]
        self.status["F"] += packet.TCP_header.flags["FIN"]
        self.status["R"] += packet.TCP_header.flags["RST"]
