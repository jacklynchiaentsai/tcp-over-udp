# Computer Networks Project: tcp-over-udp
## Description
Simplified version of the Transmission Control Protocol (TCP) that operates over User Datagram Protocol (UDP). Implementation includes a
three-way handshake for connection establishment, error logging, and a FIN request to signal the end of data transmission   
**See project_info.pdf for detailed project functionalities descripion**

## ALL SUBMITTED FILES & SHORT DESCRIPTION OF EACH 
1. README.txt : this file
2. program.txt: doc describing program DESIGN
3. screendump.txt: screen dump of a typical client-server interaction
4. tcpclient.py: program for TCP data sender
5. tcpserver.py: program for TCP data receiver
6. requirements.txt

## COMMANDS NEEDED TO RUN THE PROGRAMS 
Note: These programs should be run in order
1. newudpl 
./newudpl -p 2222:3333 -i 127.0.0.1:1234 -o 127.0.0.1:4444 -vv -L [packet_loss %]
Note: [packet_loss %] is any number in the range [0,100), would strongly advise testing with 15 just because with large [packet_loss %], 
the updated timeout value will often be extremely huge and can take long time for entire file to transfer

2. tcpserver
python3 tcpserver.py [writing_filename] 4444 127.0.0.1 1234

3. tcpclient
python3 tcpclient.py [reading_filename] 127.0.0.1 2222 500 1234

Note: writing_filename and reading_filename must be of the same file type (eg: both binary files or both text files)

## KNOWN BUGS & FEATURES 
# BUGS
1. According to ED, we are not required test if the port numbers are already used, so I did not implement this check.
The program tester should make sure that the port numbers used by newudpl, tcpclient, and tcpserver are not occupied.
2. if writing_filename and reading_filename are called the same the program will not work accordingly so make sure to name them different.

## FEATURES: functions implemented in tcpserver.py and tcpclient.py
1. checkPortNum: according to Programming Assignment 1's port num validation, check if port num is an int and within range
2. checkIPAddress: checks if IP address is valid
3. checkInt: checks if windowsize is an integer
4. formatbits: used for formatting the flags of TCP header
5. calcChecksum: calculates checksum 
6. genTCPheader: genererates 20 byte TCP header
7. updatetimeout: updates timeout value based on Sample RTT
8. clientUDPReceive: thread for client to receive UDP messages
9. clientTimer: thread for implementing TCP sender timer

## MY TESTING ENVIRONMENT
I use a windows laptop, so I installed ubuntu and ran all 3 programs on 3 separate ubuntu terminals.
Note: All 3 programs should be ran on the same localhost. I asked TAs and they say this implementation is sufficient.
