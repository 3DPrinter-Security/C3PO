#!/bin/bash

UTIL_FOLDER=$(pwd)/../C3PO_Tools
mkdir $UTIL_FOLDER
cd $UTIL_FOLDER

## check for python requirements

cd $UTIL_FOLDER
# Building XSB & MulVAL require g++, openjdk-8-jdk, bison, flex, graphviz, texlive-font-utils

# get & install XSB
wget http://xsb.sourceforge.net/downloads/XSB.tar.gz
tar -xvf XSB.tar.gz
cd XSB/build
sudo ./configure -prefix=/usr/local
./makexsb
sudo makexsb install
export PATH=$PATH:/usr/local/xsb-3.8.0/bin

# get MulVAL
cd $UTIL_FOLDER
git clone https://github.com/fiware-cybercaptor/mulval.git
cd mulval
export MULVALROOT=$(pwd)
make
cd utils
export PATH=$PATH:$(pwd)



