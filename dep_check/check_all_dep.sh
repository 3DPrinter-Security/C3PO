#!/bin/bash

HASPYTHON=''
HASPIP=''
HASMUTINY=''
HASRADAMSA=''
HASXSB=''
HASMULVAL=''
PYMODS=''

check_python(){
    if command -v python >/dev/null 2>&1; then
	HASPYTHON=1
	return 0
    else
	echo "needs python"
	return 1
    fi
}

check_pip(){
    if command -v pip >/dev/null 2>&1; then
	HASPIP=1
	return 0
    else
	echo "needs pip"
	return 1
    fi
}

check_python_modules(){
    if [ ! -z $HASPYTHON ]; then
	if ! python -c 'import inquirer' 2>/dev/null; then
	    echo "needs python inquirer module"
	    PYMODS+="inquirer "
	fi
	if ! python -c 'import nmap' 2>/dev/null; then
	    echo "needs python nmap module"
	    PYMODS+="nmap "
	fi
	if ! python -c 'import tenable_io' 2>/dev/null; then
	    echo "needs python tenable_io module"
	    PYMODS+="tenable_io "
	fi
	if ! python -c 'import scapy' 2>/dev/null; then
	    echo "needs python scapy module"
	    PYMODS+="scapy "
	fi
	if ! python -c 'import subprocess' 2>/dev/null; then
	    echo "needs python subprocess module"
	    PYMODS+="subprocess "
	fi
	if ! python -c 'import paramiko' 2>/dev/null; then
	    echo "needs python paramiko module"
	    PYMODS+="paramiko "
	fi
	if ! python -c 'import requests' 2>/dev/null; then
	    echo "needs python requests module"
	    PYMODS+="requests "
	fi
	if ! python -c 'import functools' 2>/dev/null; then
	    echo "needs python functools module"
	    PYMODS+="functools "
	fi
	if [ -z "$PYMODS" ]; then
	    return 0
	else
	    echo "Need to install additional python modules: $PYMODS"
	    return 1
	fi
    else
	return 1
    fi
}


check_mutiny(){
    if $( find ~ -name mutiny.py -quit ); then
	HASMUTINY=1
	return 0
    else
	echo "needs mutiny"
	return 1
    fi
}

check_radamsa(){
    if $( find ~ -name radamsa.c -quit ); then
	HASRADAMSA=1
	return 0
    else
	echo "needs mutiny"
	return 1
    fi
}

check_XSB(){
    if command -v xsb >/dev/null 2>&1; then
	HASXSB=1
	return 0
    else
	echo "needs XSB"
	return 1
    fi
}

check_MulVAL(){
    if $( find ~ -name mulval -quit ); then
	HASMULVAL=1
	return 0
    else
	echo "needs mulval"
	return 1
    fi
}


check_python
check_pip
check_python_modules
check_mutiny
check_radamsa
check_XSB
check_MulVAL
