import sys
import re
import socket
import struct
import threading
import time
import os

# global variables
initial_seqnum = 0
client_seqnum = initial_seqnum   # tracks the most updated 
sendbase = initial_seqnum   #keeps track of the smallest acked segment
client_acknum = 0   # temporary storage space
head_len = 5    # no optional fields in TCP header
timeout = 0.5   # set initial timeout value of 0.5 in secs
estimated_rtt = 0 # initiate as null value
dev_rtt = 0 # initiate as null value
timer_start = None # initiate as null value
time_diff = None
buffer_size = 2000    # WORK: remember to adjust
retriedSYN = False
file_dict = {} # dictionary (sequence num: data)
ack_dict = {} # dictionary (sequence num: acked?)
udpl_info = None
dupAcks = 0
retriedFIN = False
inactivity = 60
lastfileACK = 0
lastfileACKed = False

firstTimeoutUpdate = True
SYNACKed = False
FINACKed = False
finalfileACK = False
existing_timers = []
retransmitted_seqs = []
seq_timerstarts ={} # dictionary (sequence num: timer start)

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

def checkInt(var):
    try:
        int(var)
    except:
        sys.exit(">>> [Error: windowsize not an integer]")
    return int(var)

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
 
def updatetimeout(sample_rtt):
    global timeout 
    global estimated_rtt
    global dev_rtt
    global firstTimeoutUpdate
    if firstTimeoutUpdate:
        # according to TCP protocol: first Segment EstimatedRTT=SampleRTT, DevRTT=SampleRTT/2
        estimated_rtt = sample_rtt
        dev_rtt = 0.5 * sample_rtt
        firstTimeoutUpdate = False
    else:
        estimated_rtt = estimated_rtt * 0.875 + sample_rtt * 0.125
        dev_rtt = 0.75 * dev_rtt + 0.25 * abs(sample_rtt - estimated_rtt)
    
    timeout = estimated_rtt + 4 * dev_rtt

# CLIENT RECEIVE FUNCTION
def clientUDPReceive():
    global client_seqnum
    global SYNACKed
    global client_acknum
    global time_diff
    global FINACKed
    global timeout
    global sendbase
    global dupAcks
    global timer_start
    global retransmitted_seqs
    global seq_timerstarts
    global retriedFIN
    global retriedSYN
    global lastfileACK
    global lastfileACKed
    
    while True:
        full_packet, sender_info = clientSocket.recvfrom(2048)
        tcp_header = full_packet[:20]   #get the first 20 bytes
        
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
        
        #check for SYNACK
        if flags[2:] == '10010':
            # need to check if it's the 1st ack of the packet -> do not update timeout if retransmit
            if retriedSYN == False:
                time_diff = time.time() - timer_start #consider timeout situation
                updatetimeout(time_diff)
                # reset timer
                timer_start = None
                time_diff = None
                #print("new timeout: ", timeout)
            
            SYNACKed = True
            client_seqnum = ack_num
            client_acknum = seq_num + 1
        
        # FINACK
        elif flags[2:] == '10001':
            # need to check if it's the 1st ack of the packet -> do not update timeout if retransmit
            if retriedFIN == False:
                time_diff = time.time() - timer_start #consider timeout situation
                updatetimeout(time_diff)
                # reset timer
                timer_start = None
                time_diff = None
                #print("new timeout: ", timeout)
                
            FINACKed = True
            client_seqnum = ack_num - 1
            client_acknum = seq_num + 1
            # send finack later 
        
        # restart request
        elif flags[2:] == '100':
            print("<TCP connection failed on server side. Restarting...>")
            os.execl(sys.executable, sys.executable, *sys.argv) # replace current process passing in current command line args
        
        # file ACK
        elif flags[2:] == '10000':
            # update ack status
            # find the largest sequence number smaller than the ack_num and that shall be the sequence acked
            my_seq = 1
            for key in ack_dict:
                if key> my_seq and key < ack_num:
                    my_seq = key
            #print("my_seq: ", my_seq)
            ack_dict[my_seq] = True

            # check if the sequence number has been retransmitted -> if not then update timeout value
            if my_seq not in retransmitted_seqs:
                time_diff = time.time() - seq_timerstarts[my_seq]
                updatetimeout(time_diff)
                #print("first ACK, update timeout: ", timeout)
            
            if ack_num == lastfileACK:
                lastfileACKed = True
            
            elif ack_num > sendbase:
                dupAcks = 0     #reset dupAcks
                sendbase = ack_num
                # if there are currently not-yet acked segments -> start timer for oldest unACKed segment
                oldestUnacked = None
                # find oldest unacked segment
                keys = list(ack_dict.keys())
                keys.sort()
                for key in keys:
                    if ack_dict[key] == False:
                        oldestUnacked = key
                        break
                
                if oldestUnacked != None:
                    # start timer
                    thirclientTimerThread = threading.Thread(target=clientTimer, args=(oldestUnacked,))
                    thirclientTimerThread.start()
            # fast retransmit
            else:
                dupAcks += 1
                if dupAcks == 3:
                    # update timeout because TCP assumes packet is lost
                    timeout = timeout * 2
                    #print("duplicate ACKs, update timeout: ", timeout)
                    # resend segment with sequence number of ack_num
                    clientSocket.sendto(file_dict[ack_num], udpl_info)
                    dupAcks = 0     #reset dupAcks
        else:
            pass
        
        # data = full_packet[20:]
        
# TIMER THREAD FOR CLIENT
def clientTimer(seqnum):
    global ack_dict 
    global file_dict
    global udpl_info
    global timeout
    global retransmitted_seqs
    
    existing_timers.append(threading.get_ident())
    
    time.sleep(timeout)
    #print("seqnum in timer", seqnum)
    # timeout event
    if ack_dict[seqnum] == False:
        # timeout is doubled in timeout event
        # timeout = timeout * 2
        #print("timeout event, update timeout: ", timeout)
        # retransmit not-yet-acked segment with smallest sequence number
        oldestUnackedSeq = None
        # find oldest unacked segment
        keys = list(ack_dict.keys())
        keys.sort()
        for key in keys:
            if ack_dict[key] == False:
                oldestUnackedSeq = key
                break
        
        # since we're retransmitting it we add it into our retransmit records (timeout update implementation)
        retransmitted_seqs.append(oldestUnackedSeq)
        
        # don't have to check if oldestUnackedSeq is None cuz that is impossible
        clientSocket.sendto(file_dict[oldestUnackedSeq], udpl_info) 
        
        # start timer
        dupclientTimerThread = threading.Thread(target=clientTimer, args=(oldestUnackedSeq,))
        dupclientTimerThread.start()     

        # remove this timer duty is done
        existing_timers.remove(threading.get_ident())
    else:
        existing_timers.remove(threading.get_ident())
     

# taking command line parameters
if len(sys.argv) != 6:
    sys.exit(">>> [Error: Incorrect Number of Arguments]")

# note that the types are strings
filename = sys.argv[1]
udpl_addr = sys.argv[2]
udpl_port = sys.argv[3]
windowsize = sys.argv[4]
ack_port = sys.argv[5]

# error checking of command line paras
checkIPAddress(udpl_addr)
udpl_port = checkPortNum(udpl_port)
ack_port = checkPortNum(ack_port)
windowsize = checkInt(windowsize)   

udpl_info = (udpl_addr, udpl_port)

# reading file
try:
    file = open(filename, "rb")
    file_data = file.read() #file_data is a byte string
except:
    sys.exit(">>> [Error: Specified file does not exist]")

# creating udp socket
try:
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind(("localhost", ack_port))
except:
    sys.exit(">>> [ERROR: Failed Creating Socket - already used port.]")

# create separate thread to take incoming messages(UDP)
clientRecvThread = threading.Thread(target=clientUDPReceive)
clientRecvThread.start()


# 3 way handshake
# sending SYN request
syn_flags = formatbits(0,1,0)
syn_header = genTCPheader(ack_port, udpl_port, client_seqnum, 0, syn_flags, windowsize) #acknum = 0
syn_packet = syn_header
# implement timeout and retry
retry = 0 
while retry < 7:    # set maximum amount of retries to be 7
    clientSocket.sendto(syn_packet, udpl_info) 
    if retry == 0:   # only start timer for first transmission
        timer_start = time.time()
    else:
        retriedSYN = True
    
    time.sleep(timeout)
    
    if SYNACKed:    # synack successful
        break
    else:   
        retry += 1

if SYNACKed == False:
    print(">>> [ERROR: Reached maximum retries. TCP connection failed.]")
    print(">>> [Exiting]")   
    os._exit(1) # terminate the program with error code   

# send final ACK of 3 way handshake
# SYNACKed = False
synackack_flags = formatbits(1,0,0)
synackack_header = genTCPheader(ack_port, udpl_port, client_seqnum, client_acknum, synackack_flags, windowsize)
synackack_packet = synackack_header
clientSocket.sendto(synackack_packet, udpl_info)
print("< TCP connection established >")
lastfileACK = len(file_data) + 1
# print("last file ACK", lastfileACK)


# sending file information 2000 bytes at a time
for i in range(0, len(file_data), buffer_size):
    chunk = file_data[i:i+buffer_size]
    #print(chunk)

    file_flags = formatbits(0,0,0)
    file_header = genTCPheader(ack_port, udpl_port, client_seqnum, 0, file_flags, windowsize, chunk)
    file_packet = file_header + chunk
    
    # save packet information in case of retransmit
    file_dict[client_seqnum] = file_packet
    ack_dict[client_seqnum] = False
    seq_timerstarts[client_seqnum] = time.time()
    
    if len(existing_timers) == 0:     # if timer currently not running
        # open a new thread for timer: timer for oldest unACKed segment
        clientTimerThread = threading.Thread(target=clientTimer, args=(client_seqnum,))
        clientTimerThread.start()
    
    clientSocket.sendto(file_packet, udpl_info)
    client_seqnum += len(chunk)
    
# should give enough time between last file packet and and finreq for all file data to be written on server side
while lastfileACKed == False:
    time.sleep(1)
    
# send last chunk with FIN request
finreq_flags = formatbits(0,0,1)
retry = 0
while retry < 7:
    finreq_header = genTCPheader(ack_port, udpl_port, client_seqnum, 0, finreq_flags, windowsize)
    finreq_packet = finreq_header
    clientSocket.sendto(finreq_packet, udpl_info)
    
    if retry == 0:   # only start timer for first transmission
        timer_start = time.time() # only used for SYN and FIN so it's ok
    else:
        retriedFIN = True
    
    time.sleep(timeout)
    if FINACKed:
        # send an ack to finack
        finackack_flags = formatbits(1,0,0)
        finackack_header = genTCPheader(ack_port, udpl_port, client_seqnum, client_acknum, finackack_flags, windowsize)
        finackack_packet = finackack_header
        clientSocket.sendto(finackack_packet, udpl_info)
        time.sleep(timeout) # timed wait
        print("< TCP Connection Closed >")
        os._exit(0) # terminate client
    else:
        retry += 1

if FINACKed == False:
    print(">>> [Error: Reached maximum retries for FIN requests. Terminating client. ]")
    os._exit(1) # terminate client

# when to update timer
# sample RTT
# detect packet loss (timer expire, receive 3 duplicate ACKs)

