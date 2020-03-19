import socket
from time import sleep
import threading
import sys, signal
import argparse
import resource
import DoS.many_First_Packets as dos_first
import DoS.many_TCP_connections as dos_tcp
import DoS.many_Data_Packets as dos_data

def run(hostdata, pcapdata, test_rec, outfile):
    print("3) Running DoS tests")
    dos_tcp.run(hostdata, pcapdata, test_rec, outfile)
    dos_first.run(hostdata, pcapdata, test_rec, outfile)
    dos_data.run(hostdata, pcapdata, test_rec, outfile)
