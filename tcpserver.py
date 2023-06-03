import sys
import re
import struct
from socket import *
import os
import time

# global variables
server_seqnum = 0
server_acknum = 0
expected_seqnum = 1
head_len = 5    # no optional fields in TCP header
timeout = 0.5   # set initial timeout value of 0.5 in secs
estimated_rtt = 0 # initiate as null value
dev_rtt = 0 # initiate as null value
timer_start = None
time_diff = None
connectionInfo = None   # will store a tuple of clientInfo once connection is established
buffer_size = 2000  #established fact. I set so myself

isGap = False
lowerGapseq = None
upperGapseq = None

nextSegmentPacket = None
nextSegmentInfo = None
       
# helper functions
def checkPortNum(portNum):
    # takes in string version of portNum and returns integer version if valid
    try:
        portNum = int(portNum)
    except:
        sys.exit(">>> [ERROR: Port number not an integer]")
    
    if portNum < 1024 or portNum > 65535:
        sys.exit(">>> [ERROR: Port number out of range]")
    
    return portNum

def checkIPAddress(ip):
    # valid: four integers ranging from 0-255 separated by 3 dots
    pattern = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if not (re.search(pattern,ip)):
        sys.exit(">>> [ERROR: Invalid IP Address]")

# format the flags into an 8 bit binary variable
def formatbits(A,S,F,R=0):
    # unused flags
    C,E,U,P = 0,0,0,0
    flag_byte = (C<<7) | (E<<6) | (U<<5) | (A<<4) | (P<<3) | (R<<2) | (S<<1) | F
    return flag_byte   # returns decimal representation -> to use convert to binary bin(flag_byte)
        
def calcChecksum(data):
    # print(data)
    # If the length of the data is odd, pad with a zero byte
    if len(data) % 2 != 0:
        data += b'\x00'

    # Sum all 16-bit words
    total = sum(struct.unpack('!%sH' % (len(data) // 2), data))

    # Fold the sum to 16 bits
    total = (total & 0xffff) + (total >> 16)

    # Take the one's complement of the result
    checksum = (~total) & 0xffff

    return checksum

def genTCPheader(src_port, dst_port, seq_num, ack_num, flags, window_size, data = "".encode()):
    global head_len
    # 20-byte TCP header (0 is the initial checksum value)
    header_init = struct.pack('!HHIIBBHHxx', src_port, dst_port, seq_num, ack_num, head_len, flags, window_size, 0)
    check_data = header_init + data
    checksum = calcChecksum(check_data)
    packed_header = struct.pack('!HHIIBBHHxx', src_port, dst_port, seq_num, ack_num, head_len, flags, window_size, checksum)
    return packed_header
        
# note that the types are strings
filename = sys.argv[1]
listening_port = sys.argv[2]
address_for_acks = sys.argv[3]
port_for_acks = sys.argv[4]

# error checking of command line paras
listening_port = checkPortNum(listening_port)
checkIPAddress(address_for_acks)
port_for_acks = checkPortNum(port_for_acks)
udplInfo = (address_for_acks, port_for_acks)

# open file for writing
write_file = open(filename, "wb")

#setting up UDP socket
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(("localhost", listening_port))

# taking command line parameters
if len(sys.argv) != 5:
    sys.exit(">>> [Error: Incorrect Number of Arguments]")      

# start receiving packets from client
while True:
    full_packet, senderInfo = serverSocket.recvfrom(2048)
    tcp_header = full_packet[:20]
    
    # unpacking TCP header
    tcp_header = struct.unpack('!HHIIBBHHxx', tcp_header)
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq_num = tcp_header[2]
    ack_num = tcp_header[3]
    head_len = tcp_header[4]
    flags = str(bin(tcp_header[5]))  # convert into binary number then to string
    window_size = tcp_header[6]
    checksum = tcp_header[7]
    
    # checksum detection
    test_checksum = calcChecksum(full_packet)
    if test_checksum !=0:
        print(">>> [ERROR: checksum mismatch, packet discarded]")
        continue
    
      
    # SYN request
    if flags[2:] == '10':
        synack_flags = formatbits(1,1,0)
        synack_header = genTCPheader(listening_port, port_for_acks, server_seqnum, seq_num+1, synack_flags, window_size)
        synack_packet = synack_header
        # prevent packet loss: perform retry
        serverSocket.sendto(synack_packet, udplInfo)    # send SYNACK back
            
    # receives ACK of SYNACK
    elif flags[2:] == '10000':
        print("< TCP connection established >")
        connectionInfo = senderInfo
    
    # intermediatary file send
    # WORK: need to implement sending ACKs to each packet
    else:
        
        # first check if connection is valid (TCP)
        if connectionInfo == None:
            # server did not establish connection with client -> send a reset request
            reset_flags = formatbits(0,0,0,1)
            reset_header = genTCPheader(listening_port, port_for_acks, 0, 0, reset_flags, window_size)
            reset_packet = reset_header
            serverSocket.sendto(reset_packet, udplInfo)
            continue    
        
        # intermediatary write
        if flags[2:] == '0':
            # arrival of out of order segment -> gap detected
            if seq_num > expected_seqnum:
                # what if there's already a gap: widen the gap
                if isGap:
                    upperGapseq = seq_num
                else:
                    isGap = True
                    lowerGapseq = expected_seqnum
                    upperGapseq = seq_num
                
                dupack_flags = formatbits(1,0,0)
                dupack_header = genTCPheader(listening_port, port_for_acks, 0, lowerGapseq, dupack_flags, window_size)
                dupack_packet = dupack_header
                # send duplicate ACKs
                serverSocket.sendto(dupack_packet, udplInfo)
                serverSocket.sendto(dupack_packet, udplInfo)
                
            elif isGap:
                # arrival of segment that starts at lower end of gap
                if seq_num == lowerGapseq:
                    # check if gap is filled
                    if lowerGapseq == upperGapseq:  #CHECK
                        # first still need to write data into file
                        file_data = full_packet[20:]
                        write_file.write(file_data)
                        isGap = False
                        lowerGapseq = None
                        upperGapseq = None
                        
                        expected_seqnum = seq_num + len(file_data)
                        # immediate send ACK
                        immack_flags = formatbits(1,0,0)
                        immack_header = genTCPheader(listening_port, port_for_acks, 0, expected_seqnum, immack_flags, window_size)
                        immack_packet = immack_header
                        serverSocket.sendto(immack_packet, udplInfo)
                        
                    #right order but gap not completely filled
                    else:    
                        # write data into file: this is the correct order
                        file_data = full_packet[20:]
                        write_file.write(file_data)
                        # update lowerGapseq to next
                        lowerGapseq = seq_num + len(file_data)
                    
                        # immediate send ACK
                        immack_flags = formatbits(1,0,0)
                        immack_header = genTCPheader(listening_port, port_for_acks, 0, lowerGapseq, immack_flags, window_size)
                        immack_packet = immack_header
                        serverSocket.sendto(immack_packet, udplInfo)
            
            # since we checked for gap first we know at this point all data up to expected seq # already ACKed  
            # arrival of in-order segment      
            elif seq_num == expected_seqnum:
                # writing data into file
                file_data = full_packet[20:]
                write_file.write(file_data)
                
                # no need to implement delayed ACK yayy
                expected_seqnum = seq_num + len(file_data)
                fileack_flags = formatbits(1,0,0)
                fileack_header = genTCPheader(listening_port, port_for_acks,0, expected_seqnum, fileack_flags, window_size)
                fileack_packet = fileack_header
                serverSocket.sendto(fileack_packet, udplInfo)
        
        #FIN request from client
        elif flags[2:] == '1':
            write_file.close()  # finish writing all of file
            # send back FIN+ACK
            finack_flags = formatbits(1,0,1)
            finack_header = genTCPheader(listening_port, port_for_acks, ack_num, seq_num+1, finack_flags, window_size)
            finack_packet = finack_header
            serverSocket.sendto(finack_packet, udplInfo)
            print("< TCP Connection Closed >")
            os._exit(0) # terminate server

        else:
            pass
            # file_data = full_packet[20:]
            # write_file.write(file_data)
        
# set address None 
