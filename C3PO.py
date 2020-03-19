#!/usr/bin/python

from scapy.all import *
import indiv_tools.data_transfer as data_transfer
import indiv_tools.known_vuln as known_vuln
import indiv_tools.fuzzer as fuzzer
import indiv_tools.dos_tests as dos_tests
import argparse
import inquirer

def main():
    print("C3PO: Connected 3D Printer Observer")
    print("-----------------------------------")
    parser=argparse.ArgumentParser(description='Run a set of tests against a 3D printer')
    
    parser.add_argument('--pcap', '-p', required=True, type=str, help='Input pcap file')
    parser.add_argument('--testIP', '-i', required=True, type=str, help='Device under test\'s IP address')
    parser.add_argument('--file', '-o', required=False, type=str, help='Output file')

    parser.add_argument('-A', action='store_true', help='Run all individual machine tests')

    parser.add_argument('-x', action='store_true', help='Run Data Transfer Tests for individual machine')
    parser.add_argument('-k', action='store_true', help='Run Nikto, Nmap, and Nessus for individual machine')
    parser.add_argument('-f', action='store_true', help='Run Fuzzing and Application-based Tests for individual machine')
    parser.add_argument('-d', action='store_true', help='Run DoS Tests for individual machine')

    args = parser.parse_args()
    pcapData=rdpcap(args.pcap)

    # 1) Extract Host Data from pcap
    hostData = data_transfer.findHosts(pcapData)
    print("Found IP addresses:")
    receiver = "1) Receiver: " + hostData.receiver + ":" + str(hostData.rec_port[0])
    sender = "2) Sender: " + hostData.sender + ":" + str(hostData.send_port[0])
    questions = [
            inquirer.List('ip',
                message = "Choose the IP and port of the printer you wish to test?",
                choices = [receiver, sender],
                ),
    ]
    answer = inquirer.prompt(questions)
    test_rec = False
    if answer['ip'] is receiver:
        test_rec = True

    # 2) Run Data Transfer Tests
    if args.A or args.x:
        data_transfer.run(pcapData, hostData, args.testIP, args.file)
    
    # 3) Run Nikto, Nmap, and Nessus for Known Vulnerabilities
    if args.A or args.k:
        known_vuln.run(hostData, test_rec, args.file)

    # 4) Run DoS tests
    if args.A or args.d:
        dos_tests.run(pcapData, hostData, test_rec, args.file)

    # 5) Run Fuzzer tests
    if args.A or args.f:
        fuzzer.run(args.pcap, hostData, test_rec, args.file)

if __name__=='__main__':
    main()
