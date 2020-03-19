#!/bin/bash

UTIL_FOLDER=$(pwd)/../C3PO_Tools
mkdir $UTIL_FOLDER
cd $UTIL_FOLDER

# get mutiny fuzzer
git clone https://github.com/Cisco-Talos/mutiny-fuzzer.git

cd mutiny-fuzzer

# get radamsa
## just download zip of ver 0.3 
git clone https://github.com/aoh/radamsa

tar -xvf mutiny-fuzzer/radamsa-0.3.tar.gz

cd radamsa-0.3
make

## check for python requirements
pip install scapy inquirer nikto nmap tenable_io
