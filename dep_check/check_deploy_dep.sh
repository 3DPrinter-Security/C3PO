#!/bin/bash

HASPYTHON=''
HASPIP=''
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
	if ! python -c 'import nmap' 2>/dev/null; then
	    echo "needs python nmap module"
	    PYMODS+="nmap "
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
check_XSB
check_MulVAL
