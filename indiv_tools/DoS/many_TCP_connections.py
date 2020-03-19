#!/usr/bin/python

import socket
from time import sleep
import threading
import sys, signal
import argparse
import resource


streams = []

count = 0
lock = threading.Lock()

def worker(num, ip, port, send=False):
    connected=False
    while (not connected):
        try:
            lock.acquire()
            print 'Worker #%3d Starting' % int(num)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            #s = socket.create_connection((ip, port))
            connected=True
            print "Connection #%3d Setup" % int(num)
            lock.release()
        except Exception as msg:
            print "Connected #%3d Setup Refused" % int(num)
            print(msg)
        finally:
            if lock.locked():
                lock.release()
    try:
        while True:
            if send:
                s.send('a')
            a=1
            sleep(1)
    except KeyboardInterrupt:
        print('exiting')
    finally:
        s.close()

def run(pcapData, hostData, test_rec, outfile):

    print("\tRunning DoS tests using many TCP connections")

    resource.setrlimit(resource.RLIMIT_NOFILE, (4000, 4000))
    
    num_connections=2000

    if test_rec:
        ip = hostData.receiver
        port = hostData.rec_port[0]
    else:
        ip = hostData.sender
        port = hostData.send_port[0]

    threads = []

    for i in range(num_connections):
        t = threading.Thread(target=worker, args=(i, ip, port, data, False, False, False))
        threads.append(t)
        t.start()
        sleep(0.01)

    for i in range(num_connections):
        threads[i].join(1000)

    print "All Threads Done!"
