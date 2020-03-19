# C3PO
C3PO systematically identifies individual 3D printer's security issues and identify how a its network deployment impacts a network attacker's ability to (1) make defective parts, (2) steal proprietary information/data, or (3) cause 3D printer downtime. 

C3PO is composed of two parts: (1) a standalone 3D Printer analysis tool, and (2) a network deployment analysis tool. The standalone tools analyzes four areas for potential vulnerabilities: (a) data transfer--checking for the use of encryption, (b) availability--checking for susceptibility to DoS, (c) malicious inputs--fuzzing network inputs, and (d) unused open ports and known exploits. These can be run all together (-A) or individually (-x for data transfer, -d for availability, -f for malicious inputs, and -k for known exploits). 

# Install
C3PO requires: python and pip for additional python modules that are utilized 
- Checking malicious inputs uses Cisco's Mutiny Fuzzer, which requires radamsa
- The network deployment module uses MulVal, which requires XSB
