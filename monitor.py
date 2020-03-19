#!/usr/bin/env python
#------------------------------------------------------------------
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Co-Author Lilith Wyatt (liwyatt)
#------------------------------------------------------------------
# Copyright (c) 2014-2017 by Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Cisco Systems, Inc. nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#------------------------------------------------------------------
#
# Copy this file to your project's mutiny classes directory to
# implement a long-running thread to monitor your target
# This is useful for watching files, logs, remote connections,
# PIDs, etc in parallel while mutiny is operating
# This parallel thread can signal Mutiny when it detects a crash
#
#------------------------------------------------------------------

from scapy.all import *
import time

# Send the recorded first packet to the printer. Return false if received unexpected results.
def test_packet(ip, port, data, resp):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        for i in data:
            s.send(i)
            sleep(0.9)
        response = s.recv(8192)
        if(set(response).intersection(set(resp))>(len(resp)/4)):
            return True
        else:
            return False
    except:
        print "Connection Refused"
        return True

def get_pcap_paths(targetIP):
    first_pcap_path = "mutiny_fuzzer/{0}_first.pcap".format(targetIP)
    response_pcap_path = "mutiny_fuzzer/{0}_response.pcap".format(targetIP)
    return [first_pcap_path,response_pcap_path]

class Monitor(object):
    # This function will run asynchronously in a different thread to monitor the host
    def monitorTarget(self, targetIP, targetPort, signalMain):
        pcap_paths = get_pcap_paths(targetIP)

        pcapData = rdpcap(pcap_paths[0])
        respData = rdpcap(pcap_paths[1])
        while True:
            print("MONITORING")
            data = pcapData[0][TCP].payload
            resp = respData[0][TCP].payload
            if not test_packet(targetIP, targetPort, data, resp):
                signalMain() #Sends a SigInt to the mutiny fuzzer - see mutiny.py for handling.
        pass
