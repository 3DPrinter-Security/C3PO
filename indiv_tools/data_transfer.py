#!/usr/bin/env python

## Usage example: python data_transfer.py -i <pcap file> -o <output file>

from scapy.all import *
import argparse
import re
from binascii import hexlify, unhexlify
import string
import struct
import math
import zlib
import zipfile
import io
from scipy.stats import chisquare
import numpy as np
from statsmodels.tsa.stattools import acf
import csv

class IPdata:
    def __init__(self, sender='', receiver='', version=0, send_port=[], rec_port=[]):
        self.sender = sender
        self.receiver = receiver
        self.version = version
        self.send_port=send_port
        self.rec_port=rec_port

def isIPv4(ipAddr):
    a = ipAddr.split('.')
    if len(a) != 4:
        return False
    return True

def getIPv(version):
    IPv=''
    if version == 4:
        IPv = 'IP'
    elif version == 6:
        IPv='IPv6'
    else:
        print("error in IP version type")
    return IPv

def check4Broadcast(address):
    if isIPv4(address):
        splitAddress=address.split('.')
        if splitAddress[0] >= '224' and splitAddress[0] <= '239':
            return True
        if splitAddress[3]=='255':
            return True
        return False
    else:
        ##TODO: Update for IPv6
        return False


def pktDataLen(pkt):
    if pkt.haslayer(Raw):
        return len(pkt[Raw].load)
    else:
        return 1

def findHosts(pkts):
    pairs={}
    version=None
    for pkt in pkts:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if not check4Broadcast(pkt[IP].src):
                route=str(pkt[IP].src)+'-'+str(pkt[IP].dst)
                route2=str(pkt[IP].dst)+'-'+str(pkt[IP].src)
                if route not in pairs and route2 not in pairs:
                    pairs[route]=pktDataLen(pkt)
                elif route2 not in pairs and route in pairs:
                    pairs[route]+=pktDataLen(pkt)
                elif route not in pairs and route2 in pairs:
                    pairs[route2]+=pktDataLen(pkt)       
                else:
                    pairs[route]+=pktDataLen(pkt)
        elif pkt.haslayer(IPv6) and pkt.haslayer(TCP):
            if not check4Broadcast(pkt[IPv6].src):
                route=str(pkt[IPv6].src)+'-'+str(pkt[IPv6].dst)
                route2=str(pkt[IPv6].dst)+'-'+str(pkt[IPv6].src)
                if route not in pairs and route2 not in pairs:
                    pairs[route]=pktDataLen(pkt)
                elif route2 not in pairs and route in pairs:
                    pairs[route]+=pktDataLen(pkt)
                elif route not in pairs and route2 in pairs:
                    pairs[route2]+=pktDataLen(pkt)                       
                else:
                    pairs[route]+=pktDataLen(pkt)

    pairsList=sorted(pairs, key=pairs.__getitem__, reverse=True)

    #assume that the src and dst we are looking for are those with the most packets
    for i in range(0, len(pairsList)):
        senderAndReceiver=pairsList[i].split('-')    
        sender = senderAndReceiver[0]
        receiver = senderAndReceiver[1]
        #determine if using IPv4 or IPv6
        if isIPv4(sender):
            version=4
        else:
            version=6
        IPv = getIPv(version)
        foundProxy=False
        for pkt in pkts:
            if pkt.haslayer(TCP):
                if pkt[IPv].src==sender and pkt[IPv].dst==receiver:
                    # Check for http proxies
                    if pkt[TCP].dport == 3128 or pkt[TCP].sport == 3128:
                        foundProxy=True
                        break
        if not foundProxy:
            break
        
    rec_port_list=[]
    send_port_list=[]
    for pkt in pkts:
        if pkt.haslayer(TCP):
            if (pkt[IPv].src==sender and pkt[IPv].dst==receiver):
                if pkt[TCP].dport not in rec_port_list:
                    rec_port_list.append(pkt[TCP].dport)
                if pkt[TCP].sport not in send_port_list:
                    send_port_list.append(pkt[TCP].sport)

    output = IPdata(sender, receiver, version, send_port_list, rec_port_list)
    return output


class LLMNRdata:
    def __init__(self, hostnames, addrs):
        self.hostnames=hostnames
        self.addrs=addrs

class BroadcastMsgs:
    def __init__(self, exists=False, msgType=None, msgData=None):
        self.exists=exists
        self.msgType=msgType
        self.msgData=msgData


def check4Broadcasts(pkts, hostData):
    
    IPv=getIPv(hostData.version)
    broadcastAddr = ''
    if hostData.version == 4:
        broadcastAddr='224.0.0.252'
    elif hostData.version == 6:
        broadcastAddr='ff02::1:3'
    else:
        print("IP version error")

    foundBroadcast=False
    look4LLMNR=False
    LLMNRqName=[]
    LLMNRdict={}
    for pkt in pkts:
        if pkt.haslayer(IPv):
            if (pkt[IPv].src==hostData.sender or pkt[IPv].src==hostData.receiver):
                if pkt[IPv].dst==broadcastAddr:
                    foundBroadcast=True
                    if pkt.haslayer(LLMNRQuery):
                        if pkt[LLMNRQuery].qd.qname not in LLMNRqName:
                            LLMNRqName.append(pkt[LLMNRQuery].qd.qname)
                        look4LLMNR=True
            if foundBroadcast:
                if look4LLMNR:
                    if pkt.haslayer(LLMNRResponse) and pkt[IPv].src != hostData.sender:
                        if pkt[LLMNRResponse].an.rrname[:-1] not in LLMNRdict:
                            LLMNRdict[pkt[LLMNRResponse].an.rrname[:-1]]=[pkt[LLMNRResponse].an.rdata]
                        else:
                            if pkt[LLMNRResponse].an.rdata:
                                LLMNRdict[pkt[LLMNRResponse].an.rrname[:-1]].append(pkt[LLMNRResponse].an.rdata)
    msgType=''
    if look4LLMNR:
        msgType='LLMNR'        
        if len(LLMNRdict.values())>0:
            msgData = LLMNRdata(list(LLMNRdict.keys()), list(LLMNRdict.values()[0]))
            output = BroadcastMsgs(foundBroadcast, msgType, msgData)
        else:
            output=BroadcastMsgs(foundBroadcast, msgType)
    #print(output.exists, output.msgType, output.msgData.hostnames, output.msgData.addrs)
    else:
        output=BroadcastMsgs(foundBroadcast)
    return output



class PktData:
    def __init__(self, pkts=0, dataPkts=0, dataBytes=0, aboveThresh=0,
                 aboveThreshwZeros=0, numPics=0, gzips=0, xzs=0,
                 zips=0, highEntropy=0, zeroEntropy=0, midEntropy=0,
                 highPval=0, lowPval=0, highCorr=0, lowCorr=0,
                 smallPkts=0):
        self.pkts=pkts
        self.dataPkts=dataPkts
        self.dataBytes=dataBytes
        self.aboveThresh=aboveThresh
        self.aboveThreshwZeros=aboveThreshwZeros
        self.numPics=numPics
        self.picTypes=[]
        self.gzips=gzips
        self.xzs=xzs
        self.zips=zips
        self.highEntropy=highEntropy
        self.zeroEntropy=zeroEntropy
        self.midEntropy=midEntropy
        self.highPval=highPval
        self.lowPval=lowPval
        self.highCorr=highCorr
        self.lowCorr=lowCorr
        self.smallPkts=smallPkts
        self.allPktData=[]
        self.notIDdPktData=[]
        self.IDdPktData=[]
        

def countPrintableChars(dataString):
    printableChars=0
    for i in str(dataString):
        if i in string.printable:
            printableChars+=1
    return printableChars


def countZeros(dataString):
    numZeros=0
    for i in str(dataString):
        if i == '\x00':
            numZeros+=1
    return numZeros

def getRatio(num, den):
    if den>0:
        return float(num)/float(den)
    else:
        return 0

class PicData:
    def __init__(self, foundPic=False, foundEnd=False, bytesLeftInChunk=0, fileFmt=''):
        self.foundPic=foundPic
        self.foundEnd=foundEnd
        self.bytesLeftInChunk=bytesLeftInChunk
        self.fileFmt=fileFmt
        self.data=[]


def picDataRemaining(data, fileFmt, index=0):
    foundEnd=False
    foundPic=True
    if fileFmt=='PNG':
        if len(data)>index:
            data=data[index:]
        else:
            return PicData(foundPic, foundEnd, (index-len(data)), 'PNG')
        '''
        while data:
            dataLength=struct.unpack(">I", data[0:4])[0]
            chunkType=data[4:8]
            if chunkType =='IEND':
                foundEnd=True
            rem=len(data)
            if rem < (dataLength+12):
                break
            data=data[(12+dataLength):]
        if(foundEnd and (dataLength+12)==rem):
            foundPic=False
        return PicData(foundPic, foundEnd, ((dataLength+12)-rem), 'PNG')
        '''
        if re.search('IEND', data):
            foundEnd=True
            foundPic=True
        return PicData(foundPic, foundEnd, 0, 'PNG')
    elif fileFmt=='JPEG':
        if re.search('\xff\xd9', data):
            foundPic=False
            foundEnd=True
        return PicData(foundPic, foundEnd, 0, 'JPEG')
    elif fileFmt=='YUV':
        if index>len(data):
            return PicData(foundPic, foundEnd, (index-len(data)), 'YUV')
        else:
            foundPic=True
            foundEnd=True
            return PicData(foundPic, foundEnd, 0, 'YUV')
    else:
        foundPic=False
        foundEnd=False
        return PicData(foundPic, foundEnd, 0, 'other')
         
            
def check4pics(pkt):
    foundPic=False
    picData=PicData()
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        evalData=str(pkt[Raw].load)
        if pkt.haslayer(Padding):
            evalData+=str(pkt[Padding].load)
        if re.search('\x89PNG\r\n\x1a\n' ,evalData):
            foundPic=True
            data = re.split('\x89PNG\r\n\x1a\n' ,evalData)[1]
            picData=picDataRemaining(data, 'PNG')
            if picData.foundEnd==True:
                foundPic=False
        if re.search('JFIF' , evalData):
            foundPic=True
            data=re.split('\xff\xd8\xff\xe0', evalData)[1]
            dataLength=struct.unpack(">H", data[0:2])[0]
            Xthumbnail=struct.unpack(">B", data[14])[0]
            Ythumbnail=struct.unpack(">B", data[15])[0]
            n = Xthumbnail*Ythumbnail
            data=data[(dataLength+(3*n)):]
            while data[0] == '\xff':
                dataLength=struct.unpack(">H", data[2:4])[0]
                data=data[(dataLength+2):]
            picData=picDataRemaining(data, 'JPEG')
        '''
        if re.search('\x00\x02\x58\x10\x00\x00\x01\x40\x00\x00\x00\xf0\x00\x00\x00\x01', evalData):
            fountPic=True
            data=re.split('\x00\x02\x58\x10\x00\x00\x01\x40\x00\x00\x00\xf0\x00\x00\x00\x01', evalData)[1]
            picData=picDataRemaining(data, 'YUV', 153600)
        '''
    return PicData(picData.foundPic, picData.foundEnd, picData.bytesLeftInChunk, picData.fileFmt)

def check4gzipStart(pkt):
    foundGzip=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load
    if re.search('\x1f\x8b\x08\x00', evalData):
        foundGzip=True
    return foundGzip

def check4xzStart(pkt):
    foundXZ=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load    
    if re.search('\xfd\x37\x7a\x58\x5a\x00', evalData):
        foundXZ=True
    return foundXZ

def check4zipStart(pkt):
    foundZip=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load    
    if re.search('\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00', evalData):
        foundZip=True
    return foundZip

def check4gzipEnd(pkt, first=False):
    foundEnd=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load
    evalData=''.join(evalData)
    if not first:
        if re.search('\x00\x0d\x0a--boundary', evalData):
            foundEnd=True
    if re.search('\x00\x0d\x0a', evalData):
        foundEnd=True
#    if re.search('\x00$', evalData):
#        foundEnd=True
    return foundEnd


def check4gzipHttp(pkt):
    foundGzipHttp=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load
    if re.search('\x0d\x0a\x1f\x8b\x08\x00', evalData) and not re.search('\x0d\x0a\x0d\x0a\x1f\x8b\x08\x00', evalData):
        foundGzipHttp=True
    return foundGzipHttp

def getGzipHttp(data):
    return data.split('\x0d\x0a')
            
def check4gzipEndConn(pkt, ports=(None,None)):
    foundEnd=False
    if ports[0] is not None and ports[1] is not None and pkt.haslayer(TCP):
        if not((ports[0] == pkt[TCP].sport or ports[0] == pkt[TCP].dport) and (ports[1] == pkt[TCP].sport or ports[1] == pkt[TCP].dport)):
            foundEnd=True
    return foundEnd

def check4xzEnd(pkt):
    foundEnd=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load    
    if re.search('\x59\x5a$', evalData):
        foundEnd=True
    return foundEnd

def check4zipEnd(pkt):
    foundEnd=False
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load    
    if re.search('\x50\x4b\x05\x06\x00\x00\x00\x00', evalData):
        foundEnd=True
    return foundEnd

def check4STLbinaryStart(pkt):
    foundSTL=False
    length=0
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load
    if re.search('^\x00*solid[ a-zA-Z0-9 ]*\x00+', evalData):
        header=re.search('^\x00*solid[ a-zA-Z0-9 ]*\x00+', evalData).group(0)
        if len(header)>79:
            foundSTL=True
            data=re.split('^\x00*solid[ a-zA-Z0-9 ]*\x00+', evalData)[1][0:4]
            flip=data[::-1]
            length=int(flip.encode('hex'),16)*50
            length-=(len(evalData)-len(header))
    return (foundSTL, length)

def getSTLlength(pkt):
    if pkt.haslayer(Raw):
        evalData=pkt[Raw].load
        if pkt.haslayer(Padding):
            evalData+=pkt[Padding].load
    length=evalData[80:84]
    return length

def calcEntropy(data):
    countDict={}
    dataLen=float(len(data))
    for i in data:
        if i in countDict:
            countDict[i]+=1
        else:
            countDict[i]=1
    H=0.0
    for i in countDict:
        p=float(countDict[i])/dataLen
        entropy=p*math.log(p,2)
        H-=entropy
    return H

def isHighEntropy(H, length):
    if H == 0.0:
        return False
    out=False
    if length>128:
        if H > 6.0:
            out=True
    else:
        if H > (0.26+1.184*math.log(length)):
            out=True
    return out


def possiblyString(H, length):
    out=False
    if H < 5.75:
        out=True
    return out

def isHighPval(pVal, length):
    out=False
    if length>4:
        if pVal>0.01:
            out=True
    else:
        if pVal > (0.47+0.176*length):
            out=True
    return out

def isHighCorr(corrCoef, length):
    out=False
    if length<32:
        if corrCoef>0.5:
            out=True
    else:
        if corrCoef>(2.5647*(length**(-0.457))):
            out=True
    return out

def dict2array(dataDict, arraySize=256):
    out=[0]*arraySize
    for i in dataDict:
        if type(i) != int:
            out[int(i.encode('hex'),16)]=dataDict[i]
        else:
            out[i]=dataDict[i]
    return out

def calcChiSquared(data):
    countDict={}
    dataLen=float(len(data))
    for i in data:
        if i in countDict:
            countDict[i]+=1
        else:
            countDict[i]=1
    countArray=dict2array(countDict)
    expectedArray=[dataLen/256.]*256
    result=chisquare(countArray, expectedArray)
    # result contains the value, and the p-value
    # only return the p-value (for easier comparison)
    return result[1]

def str2int(data):
    out=[]
    for i in data:
        out.append(int(i.encode('hex'),16))
    return out

def estimated_autocorrelation(x):
    """
    http://stackoverflow.com/q/14297012/190597
    http://en.wikipedia.org/wiki/Autocorrelation#Estimation
    """
    n = len(x)
    if n>1:
        variance = x.var()
        x = x-x.mean()
    else:
        variance = 1
    r = np.correlate(x, x, mode = 'full')[-n:]
    result = r/(variance*n)    
    return result

def calcAutoCorrTest(data):
    if len(data)<=1:
        return 1.
    if type(data)==str:
        inData=str2int(data)
    elif type(data)==bytearray:
        inData=list(data)
    elif type(data)==list:
        if type(data[0])==str:
            inData=str2int(data)
    else:
        inData=data
    #autocorr=estimated_autocorrelation(np.asarray(inData))
    autocorr=acf(np.asarray(inData), fft=True, nlags=10)
    result=np.absolute(autocorr[1:])
    return result.max()

def median(lst):
    n = len(lst)
    s = sorted(lst)
    return (sum(s[n//2-1:n//2+1])/2.0, s[n//2])[n % 2] if n else None

def avg(lst):
    return sum(lst) / len(lst)

class EncrData:
    def __init__(self):
        self.entropy=[]
        self.chiPval=[]
        self.autoCorr=[]
        self.printable=[]
        self.pktLen=[]
        self.IDd=[]
        self.numPkts=0
        
    def addNew(self, entropyNew, chiPvalNew, autoCorrNew, printableNew, pktLenNew):
        self.entropy.append(entropyNew)
        self.chiPval.append(chiPvalNew)
        self.autoCorr.append(autoCorrNew)
        self.printable.append(printableNew)
        self.pktLen.append(pktLenNew)
        self.numPkts+=1

    def dataFromLargePkts(self, minPktSize, notID=False):
        if minPktSize==None:
            minPktSize=0
        tempEntropy=[]
        tempChiP=[]
        tempAutoCorr=[]
        tempPrintable=[]
        for i in range(0, self.numPkts):
            if notID==False:
                if self.pktLen[i] > minPktSize:
                    tempEntropy.append(self.entropy[i])
                    tempChiP.append(self.chiPval[i])
                    tempAutoCorr.append(self.autoCorr[i])
                    tempPrintable.append(self.printable[i])
            else:
                if self.pktLen[i] > minPktSize and self.IDd[i]==False:
                    tempEntropy.append(self.entropy[i])
                    tempChiP.append(self.chiPval[i])
                    tempAutoCorr.append(self.autoCorr[i])
                    tempPrintable.append(self.printable[i])
        if not tempEntropy:
            tempEntropy=[0]
        if not tempChiP:
            tempChiP=[0]
        if not tempAutoCorr:
            tempAutoCorr=[0]
        if not tempPrintable:
            tempPrintable=[0]
        return (tempEntropy, tempChiP, tempAutoCorr, tempPrintable)

    def getMedians(self, minPktSize=None, notID=False):
        if minPktSize==None and notID == False:
            return (median(self.entropy), median(self.chiPval), median(self.autoCorr), median(self.printable))
        (tempEntropy, tempChiP, tempAutoCorr, tempPrintable) = self.dataFromLargePkts(minPktSize, notID)
        return (median(tempEntropy), median(tempChiP), median(tempAutoCorr), median(tempPrintable))
            
    def getAvgs(self, minPktSize=None, notID=False):
        if minPktSize==None and notID == False:
            return (avg(self.entropy), avg(self.chiPval), avg(self.autoCorr), avg(self.printable))
        (tempEntropy, tempChiP, tempAutoCorr, tempPrintable) = self.dataFromLargePkts(minPktSize, notID)  
        return (avg(tempEntropy), avg(tempChiP), avg(tempAutoCorr), avg(tempPrintable))
    
    def getMins(self, minPktSize=None, notID=False):
        if minPktSize==None and notID == False:
            return (min(self.entropy), min(self.chiPval), min(self.autoCorr), min(self.printable))
        (tempEntropy, tempChiP, tempAutoCorr, tempPrintable) = self.dataFromLargePkts(minPktSize, notID)  
        return (min(tempEntropy), min(tempChiP), min(tempAutoCorr), min(tempPrintable))
    
    def getMaxs(self, minPktSize=None, notID=False):
        if minPktSize==None and notID == False:
            return (max(self.entropy), max(self.chiPval), max(self.autoCorr), max(self.printable))
        (tempEntropy, tempChiP, tempAutoCorr, tempPrintable) = self.dataFromLargePkts(minPktSize, notID) 
        return (max(tempEntropy), max(tempChiP), max(tempAutoCorr), max(tempPrintable))    

def changeFlags(flag1, flag2):
    if flag1 and flag2:
        flag1=False
        flag2=False
    return (flag1, flag2)

    
def findEncrypt(pkts, hostData, evalSrc, threshold=0.8, csvFile=None):
    IPv=getIPv(hostData.version)
    foundTxPic=False
    foundRxPic=False
    foundTxGzip=False
    foundRxGzip=False
    foundTxXZ=False
    foundRxXZ=False
    foundTxZip=False
    foundRxZip=False    
    foundTxSTL=False
    foundRxSTL=False
    TxSTLrem=0
    RxSTLrem=0
    TxGZports=(None, None)
    RxGZports=(None, None)    
    sentData=PktData()
    RxData=PktData()
    sentRaw=EncrData()
    RxRaw=EncrData()
    sentRaw_IDd=EncrData()
    RxRaw_IDd=EncrData()
    sentRaw_notIDd=EncrData()
    RxRaw_notIDd=EncrData()    
    for pkt in pkts:
        pktData=''
        if pkt.haslayer(IPv):
            if (pkt[IPv].src==evalSrc):
                sentData.pkts+=1
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    if len(pkt[Raw].load) >= 1:
                        pktData=str(pkt[Raw].load)
                        if pkt.haslayer(Padding):
                            pktData+=str(pkt[Padding].load)
                        dataInPkt=len(pktData)
                        sentData.allPktData.append(pktData)
                        if dataInPkt<128:
                            sentData.smallPkts+=1
                        sentData.dataBytes+=dataInPkt
                        sentData.dataPkts+=1
                        sentPktEntropy=calcEntropy(pktData)
                        sentPktChiSquared=calcChiSquared(pktData)
                        sentPktAutoCorr=calcAutoCorrTest(pktData)
                        sentPktPrintableChars=getRatio(countPrintableChars(str(pkt[Raw])), dataInPkt)
                        sentRaw.addNew(sentPktEntropy, sentPktChiSquared, sentPktAutoCorr, sentPktPrintableChars, dataInPkt)
                        if isHighEntropy(sentPktEntropy, dataInPkt):
                            sentData.highEntropy+=1
                        elif sentPktEntropy == 0.0:
                            sentData.zeroEntropy+=1
                        elif possiblyString(sentPktEntropy, dataInPkt):
                            sentData.midEntropy+=1
                        if isHighPval(sentPktChiSquared, dataInPkt):
                            sentData.highPval+=1
                        if isHighCorr(sentPktAutoCorr, dataInPkt):
                            sentData.highCorr+=1
                        if foundTxPic or foundTxGzip or foundTxXZ or foundTxSTL or foundTxZip:
                            sentData.aboveThresh+=1
                            sentData.aboveThreshwZeros+=1
                            sentRaw.IDd.append(True)
                            sentRaw_IDd.addNew(sentPktEntropy, sentPktChiSquared, sentPktAutoCorr, sentPktPrintableChars, dataInPkt)
                        if foundTxPic:
                            picData=picDataRemaining(str(pktData), picData.fileFmt, picData.bytesLeftInChunk)
                            foundTxPic=picData.foundPic
                            if picData.foundEnd:
                                sentData.numPics+=1
                                sentData.picTypes.append(picData.fileFmt)
                        elif foundTxGzip:
                            if check4gzipEnd(pkt):
                                foundTxGzip=False
                                sentData.gzips+=1
                            elif check4gzipEndConn(pkt, TxGZports):
                                foundTxGzip=False
                                sentData.gzips+=1
                        elif foundTxXZ:
                            if check4xzEnd(pkt):
                                foundTxXZ=False
                                sentData.xzs+=1
                        elif foundTxZip:
                            if check4zipEnd(pkt):
                                foundTxZip=False
                                sentData.zips+=1                                
                        elif foundTxSTL:
                            if TxSTLrem<=dataInPkt:
                                foundTxSTL=False
                            TxSTLrem-=dataInPkt
                        else:
                            picData=check4pics(pkt)
                            foundTxPic=picData.foundPic
                            foundTxGzip=check4gzipStart(pkt)
                            if foundTxGzip:
                                TxGZports=(pkt[TCP].sport, pkt[TCP].dport)
                            foundTxXZ=check4xzStart(pkt)
                            foundTxZip=check4zipStart(pkt)                            
                            (foundTxSTL, TxSTLrem)=check4STLbinaryStart(pkt)
                            if not foundTxPic and not foundTxGzip and not foundTxXZ and not foundTxSTL and not foundTxZip:
                                sentData.notIDdPktData.append(pktData)
                                sentRaw.IDd.append(False)
                                sentRaw_notIDd.addNew(sentPktEntropy, sentPktChiSquared, sentPktAutoCorr, sentPktPrintableChars, dataInPkt)
                                printableChars=countPrintableChars(str(pkt[Raw]))
                                pktPrintableRatio=getRatio(printableChars, dataInPkt)
                                if pktPrintableRatio>threshold:
                                    sentData.aboveThresh+=1
                                zeros=countZeros(str(pkt[Raw]))
                                pktZeroAndPrintRatio=getRatio((printableChars+zeros), dataInPkt)
                                if pktZeroAndPrintRatio>threshold:
                                    sentData.aboveThreshwZeros+=1
                            else:
                                sentData.IDdPktData.append(pktData)
                                sentRaw.IDd.append(True)
                                sentRaw_IDd.addNew(sentPktEntropy, sentPktChiSquared, sentPktAutoCorr, sentPktPrintableChars, dataInPkt)
                                sentData.aboveThresh+=1
                                sentData.aboveThreshwZeros+=1
                        
            elif (pkt[IPv].dst==evalSrc):
                RxData.pkts+=1
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    if len(pkt[Raw].load) >= 1:
                        pktData=str(pkt[Raw].load)
                        if pkt.haslayer(Padding):
                            pktData+=str(pkt[Padding].load)
                        dataInPkt=len(pktData)
                        RxData.allPktData.append(pktData)
                        if dataInPkt<128:
                            RxData.smallPkts+=1                        
                        RxData.dataBytes+=dataInPkt
                        RxData.dataPkts+=1
                        RxPktEntropy=calcEntropy(pktData)
                        RxPktChiSquared=calcChiSquared(pktData)
                        RxPktAutoCorr=calcAutoCorrTest(pktData)
                        RxPktPrintableChars=getRatio(countPrintableChars(str(pktData)), dataInPkt)
                        RxRaw.addNew(RxPktEntropy, RxPktChiSquared, RxPktAutoCorr, RxPktPrintableChars, dataInPkt)
                        if isHighEntropy(RxPktEntropy, dataInPkt):
                            RxData.highEntropy+=1
                        elif RxPktEntropy == 0.0:
                            RxData.zeroEntropy+=1
                        elif possiblyString(RxPktEntropy, dataInPkt):
                            RxData.midEntropy+=1
                        if isHighPval(RxPktChiSquared, dataInPkt):
                            RxData.highPval+=1
                        if isHighCorr(RxPktAutoCorr, dataInPkt):
                            RxData.highCorr+=1                            
                        if foundRxPic or foundRxGzip or foundRxXZ or foundRxSTL or foundRxZip:
                            RxData.aboveThresh+=1
                            RxData.aboveThreshwZeros+=1
                            RxRaw.IDd.append(True)
                            RxRaw_IDd.addNew(RxPktEntropy, RxPktChiSquared, RxPktAutoCorr, RxPktPrintableChars, dataInPkt)
                        if foundRxPic:
                            picData=picDataRemaining(str(pktData), picData.fileFmt, picData.bytesLeftInChunk)
                            foundRxPic=picData.foundPic
                            if picData.foundEnd:
                                sentData.numPics+=1
                                sentData.picTypes.append(picData.fileFmt)
                        elif foundRxGzip:
                            if check4gzipEnd(pkt):
                                foundRxGzip=False
                                sentData.gzips+=1
                            elif check4gzipEndConn(pkt,RxGZports):
                                foundRxGzip=False
                                sentData.gzips+=1
                        elif foundRxXZ:
                            if check4xzEnd(pkt):
                                foundRxXZ=False
                                sentData.xzs+=1
                        elif foundRxZip:
                            if check4zipEnd(pkt):
                                foundRxZip=False
                                sentData.zips+=1                                
                        elif foundRxSTL:
                            if RxSTLrem<=dataInPkt:
                                foundRxSTL=False
                            RxSTLrem-=dataInPkt
                        else:
                            picData=check4pics(pkt)
                            foundRxPic=picData.foundPic
                            foundRxGzip=check4gzipStart(pkt)
                            if foundRxGzip:
                                RxGZports=(pkt[TCP].sport, pkt[TCP].dport)
                            foundRxXZ=check4xzStart(pkt)
                            foundRxZip=check4zipStart(pkt)                            
                            (foundRxSTL,RxSTLrem)=check4STLbinaryStart(pkt)
                            if not foundTxPic and not foundRxGzip and not foundRxXZ and not foundRxSTL and not foundRxZip:
                                RxData.notIDdPktData.append(pktData)
                                RxRaw.IDd.append(False)
                                RxRaw_notIDd.addNew(RxPktEntropy, RxPktChiSquared, RxPktAutoCorr, RxPktPrintableChars, dataInPkt)
                                printableChars=countPrintableChars(str(pkt[Raw]))
                                pktPrintableRatio=getRatio(printableChars, dataInPkt)
                                if pktPrintableRatio>threshold:
                                    RxData.aboveThresh+=1
                                zeros=countZeros(str(pkt[Raw]))
                                pktZeroAndPrintRatio=getRatio((printableChars+zeros), dataInPkt)
                                if pktZeroAndPrintRatio>threshold:
                                    RxData.aboveThreshwZeros+=1
                            else:
                                RxData.IDdPktData.append(pktData)
                                RxRaw.IDd.append(True)
                                RxRaw_IDd.addNew(RxPktEntropy, RxPktChiSquared, RxPktAutoCorr, RxPktPrintableChars, dataInPkt)
                                RxData.aboveThresh+=1
                                RxData.aboveThreshwZeros+=1
    if csvFile != None:
        outData=[sentData.allPktData, sentRaw.entropy, sentRaw.chiPval, sentRaw.autoCorr, sentRaw.printable, sentRaw.pktLen, sentData.notIDdPktData, sentData.IDdPktData, RxData.allPktData, RxRaw.entropy, RxRaw.chiPval, RxRaw.autoCorr, RxRaw.printable, RxRaw.pktLen, RxData.notIDdPktData, RxData.IDdPktData, sentRaw_notIDd.entropy, sentRaw_notIDd.chiPval, sentRaw_notIDd.autoCorr, sentRaw_IDd.entropy, sentRaw_IDd.chiPval, sentRaw_IDd.autoCorr, RxRaw_notIDd.entropy, RxRaw_notIDd.chiPval, RxRaw_notIDd.autoCorr, RxRaw_IDd.entropy, RxRaw_IDd.chiPval, RxRaw_IDd.autoCorr]
        with open(csvFile, 'wb') as f:
            writer = csv.writer(f)
            writer.writerows(outData)
    return sentData, RxData


class GMCodes:
    def __init__(self, mCount=0, mDict={}, mCodePkts=0, gCount=0, gDict={}, gCodePkts=0):
        self.mCount=mCount
        self.mDict=mDict
        self.mCodePkts=mCodePkts
        self.gCount=gCount
        self.gDict=gDict
        self.gCodePkts=gCodePkts

class CountandTime:
    def __init__(self, count=0, times=[]):
        self.count=count
        self.times=times
def findGCode(pkts, hostData):
    IPv=getIPv(hostData.version)
    codeData=GMCodes()
    mCodePkts=0
    gCodePkts=0
    for pkt in pkts:
        if pkt.haslayer(IPv):
            if (pkt[IPv].src==hostData.sender and pkt[IPv].dst==hostData.receiver) or (pkt[IPv].src==hostData.receiver and pkt[IPv].dst==hostData.sender):
                if pkt.haslayer(Raw):
                    if len(pkt[Raw].load)>2:
                        pktData=pkt[Raw].load
                        if pkt.haslayer(Padding):
                            pktData+=pkt[Padding].load
                        #Find M Codes
                        pattern = '^~M[0-9].*$|^M[0-9].*$'
                        mCodes=re.findall(pattern, str(pktData), re.MULTILINE)
                        if mCodes:
                            mCodePkts+=1
                        mCodesClean=[]
                        for i in mCodes:
                            if i:
                                codeData.mCount+=1
                                mCode = re.findall('M[0-9]+', i)
                                for j in mCode:
                                    if j not in codeData.mDict:
                                        codeData.mDict[j]=CountandTime(1,[pkt.time])
                                    else:
                                        codeData.mDict[j].count+=1
                                        codeData.mDict[j].times.append(pkt.time)
                                mCodesClean.append(i.strip('\r'))
                        pattern='^G[0-9].*$'
                        gCodes=re.findall(pattern, str(pktData), re.MULTILINE)
                        if gCodes:
                            gCodePkts+=1
                        gCodesClean=[]
                        for i in gCodes:
                            if i:
                                codeData.gCount+=1
                                gCode = re.findall('G[0-9]+', i)
                                for j in gCode:
                                    if j not in codeData.gDict:
                                        codeData.gDict[j]=1
                                    else:
                                        codeData.gDict[j]+=1
                                gCodesClean.append(i.strip('\r'))
    codeData.gCodePkts=gCodePkts
    codeData.mCodePkts=mCodePkts
    return codeData

                        

def whichURIheader(value):
    # the 3 characters prior to ://
    output = ''
    if value == 'ttp':
        output = 'http'
    elif value == 'ftp':
        output = 'ftp'
    elif value == 'tcp':
        output = 'net.tcp'
    elif value == 'tps':
        output = 'https'
    else:
        print("error determining protocol: {}".format(value))
    return output

class ProtocolCounter:
    def __init__(self, http=0, ftp=0, nettcp=0, httpDict={}, ftpDict={}, nettcpDict={}):
        self.httpCount=http
        self.ftpCount=ftp
        self.nettcpCount=nettcp
        self.httpDict=httpDict
        self.ftpDict=ftpDict
        self.nettcpDict=nettcpDict
        
    def incrCount(self, value):
        if value == 'http':
            self.httpCount+=1
        elif value == 'ftp':
            self.ftpCount+=1
        elif value == 'net.tcp':
            self.nettcpCount +=1

    def addStr2Dict(self, value, string):
        if value == 'http':
            if string not in self.httpDict:
                self.httpDict[string]=1
            else:
                self.httpDict[string]+=1
        elif value == 'ftp':
            if string not in self.ftpDict:
                self.ftpDict[string]=1
            else:
                self.ftpDict[string]+=1
        elif value == 'net.tcp':
            if string not in self.nettcpDict:
                self.nettcpDict[string]=1
            else:
                self.nettcpDict[string]+=1

def findComm(pkts, hostData):
    IPv=getIPv(hostData.version)

    UDPcount=0
    TCPcount=0
    totalPkts=0
    commData=ProtocolCounter()
    for pkt in pkts:
        if pkt.haslayer(IPv):
            if (pkt[IPv].src==hostData.sender and pkt[IPv].dst==hostData.receiver) or (pkt[IPv].src==hostData.receiver and pkt[IPv].dst==hostData.sender):
                totalPkts+=1 
                if pkt.haslayer(TCP):
                    TCPcount+=1
                elif pkt.haslayer(UDP):
                    UDPcount+=1
                if TCPcount>=3 and pkt.haslayer(Raw):
                    if re.search('p://', str(pkt[Raw])):
                        URI=re.split("://", str(pkt[Raw]))
                        commType=whichURIheader(URI[0][-3:])
                        commData.incrCount(commType)
                        URIstr=''
                        for i in URI[1]:
                            if i in string.printable:
                                URIstr+=i
                        commData.addStr2Dict(commType, URIstr)
                    elif re.search('HTTP', str(pkt[Raw])):
                        HTTPcmd=re.split('/',str(pkt[Raw]))
                        commType='http'
                        commData.incrCount(commType)
                        URI=re.split('\r\n', str(pkt[Raw]))[0]
                        if URI.split('HTTP/1.1')[0]=='':
                            URIstr=URI.split('HTTP/1.1 ')[1]
                        else:
                            URIstr=URI.split('HTTP/1.1')[0]
                        commData.addStr2Dict(commType, URIstr)
    return commData


def getAvgInterval(dataList):
    interval = []
    for i in range(len(dataList)-1):
        interval.append(dataList[i+1]-dataList[i])
    avgInterval = float(sum(interval)) / float(len(interval))
    return avgInterval

class packetFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

class payloadData:
    def __init__(self, senderData=[], receiverData=[]):
        self.senderData=senderData
        self.receiverData=receiverData
    
    
def findTCPstart(pkts, hostData, numPkts=4):
    IPv=getIPv(hostData.version)
    haveSYN=False
    haveSYNACK=False
    haveACK=False
    count=0
    payloads=payloadData()
    for pkt in pkts:
        if pkt.haslayer(IPv):
            if (pkt[IPv].src==hostData.sender and pkt[IPv].dst==hostData.receiver) or (pkt[IPv].src==hostData.receiver and pkt[IPv].dst==hostData.sender):
                if pkt.haslayer(TCP):
                    if not haveSYN:
                        if (pkt['TCP'].flags & packetFlags.SYN):
                            haveSYN=True
                    elif haveSYN and not haveSYNACK:
                        if (pkt['TCP'].flags & (packetFlags.SYN | packetFlags.ACK)):
                            haveSYNACK=True
                    elif haveSYN and haveSYNACK and not haveACK:
                        if (pkt['TCP'].flags & packetFlags.ACK):
                            haveACK=True
                    elif haveACK and count < numPkts:
                        if pkt[IPv].src==hostData.sender:
                            if pkt.haslayer(Raw):
                                payloads.senderData.append(pkt['Raw'].load)
                                count+=1
                        elif pkt[IPv].src==hostData.receiver:
                            if pkt.haslayer(Raw):
                                payloads.receiverData.append(pkt['Raw'].load)
                                count+=1
                    else:
                        haveSYN=False
                        haveSYNACK=False
                        haveACK=False
                        break
    return payloads


class InitPkts:
    def __init__(self, foundGMcodes=False, likelyEncrypted=False, foundHTTP=False, foundProtocol=False):
        self.foundGMcodes=foundGMcodes
        self.likelyEncrypted=likelyEncrypted
        self.foundHTTP=foundHTTP
        self.foundProtocol=foundProtocol

def checkInitPkts(payloads):
    McodePattern = '^~M[0-9].*$|^M[0-9].*$'
    GcodePattern = '^G[0-9].*$'
    foundGMcodes=False
    likelyEncrypted=True
    foundHTTP=False
    foundProtocol=False
    combinedData=payloads.senderData+payloads.receiverData
    for i in combinedData:
        if(re.findall(McodePattern, str(i), re.MULTILINE) or re.findall(GcodePattern, str(i), re.MULTILINE)):
            foundGMcodes=True
        dataLen=len(i)
        printableData=countPrintableChars(str(i))
        if(getRatio(printableData, dataLen)>0.8):
            likelyEncrypted=False
        if re.search('p://', i):
            URI=re.split("://", i)
            commType=whichURIheader(URI[0][-3:])
            foundProtocol=True
        if re.search('HTTP', i):
            foundHTTP=True
    output=InitPkts(foundGMcodes, likelyEncrypted, foundHTTP, foundProtocol)
    return output


class PublicPrivate:
    def __init__(self, isPublic=False, ipaddrs=[]):
        self.isPublic=isPublic
        self.ipaddrs=ipaddrs

        
def checkPublicOrPrivate(hostData):
    result=PublicPrivate()
    sender=False
    receiver=False
    if hostData.version==4:
        splitSenderAddress=hostData.sender.split('.')
        splitReceiverAddress=hostData.receiver.split('.')
        if splitSenderAddress[0] == '10' or (splitSenderAddress[0]=='172' and (splitSenderAddress[1]>='16' or splitSenderAddress[1]<='31')) or (splitSenderAddress[0]=='192' and splitSenderAddress[1]=='168') or (splitSenderAddress[0]=='169' and splitSenderAddress[1]=='254'):
            sender=False
        else:
            sender=True
            result.ipaddrs.append(hostData.sender)
        if splitReceiverAddress[0] == '10' or (splitReceiverAddress[0]=='172' and (splitReceiverAddress[1]>='16' or splitReceiverAddress[1]<='31')) or (splitReceiverAddress[0]=='192' and splitReceiverAddress[1]=='168') or (splitReceiverAddress[0]=='169' and splitReceiverAddress[1]=='254'):
            receiver=False
        else:
            receiver=True
            result.ipaddrs.append(hostData.receiver)
    elif hostData.version==6:
        splitSenderAddress=hostData.sender.split(':')
        splitReceiverAddress=hostData.receiver.split(':')
        if splitSenderAddress[0]=='fc00' or splitSenderAddress[0]=='fe80':
            sender=False
        else:
            sender=True
            result.ipaddrs.append(hostData.sender)
        if splitReceiverAddress[0]=='fc00' or splitReceiverAddress[0]=='fe80':
            receiver=False
        else:
            receiver=True
            result.ipaddrs.append(hostData.receiver)
    if sender or receiver:
        result.isPublic=True
    return result

def writeLog(fileName, hostData, sentData, rxData, protocolData, broadcastData, codeData): 
    with open (fileName, 'w+') as f:
        f.write("PCAP File Analysis for 3D Printer Vulnerabilities\n")
        f.write("-----------------------------------------------------\n\n")        
        f.write("Primary sender (A): {}\n".format(hostData.sender))
        f.write("  - Sender port: {}\n".format(hostData.send_port))        
        f.write("Primary receiver (B): {}\n".format(hostData.receiver))
        f.write("  - Receiver port: {}\n".format(hostData.rec_port))
        f.write("Using IP version: {}\n\n".format(hostData.version))

        pktsTransmitted = (sentData.pkts+rxData.pkts)
        bytesTransmitted =  (sentData.dataBytes+rxData.dataBytes)
        byteUnits = 'B'
        if bytesTransmitted > 1024:
            bytesTransmitted = float(bytesTransmitted) / 1024
            byteUnits = 'kB'
        f.write("Total Packets Sent: {}, Total Bytes Transmitted = {} {}\n".format(pktsTransmitted, bytesTransmitted, byteUnits))
        publicIPcheck=checkPublicOrPrivate(hostData)
        if publicIPcheck.isPublic:
            f.write("\nPublic IP address used, possibly accessible from internet\n")
            f.write("\t {}\n".format(publicIPcheck.ipaddrs))
        f.write("\n******************************************\n\n")
        if(broadcastData.exists):
            f.write("Broadcast messages found\n")
            f.write("\tType: {}\n".format(broadcastData.msgType))
            if(broadcastData.msgType == 'LLMNR') and (broadcastData.msgData):
                f.write("\t\t - Hostname Looked Up: {}\n".format(broadcastData.msgData.hostnames))
                f.write("\t\t - Addresses Returned: {}\n".format(broadcastData.msgData.addrs))
                if hostData.receiver in broadcastData.msgData.addrs:
                    f.write("\t\t\t ** The receiving machine is {}** \n".format(broadcastData.msgData.hostnames))
        else:
            f.write("No broadcast messages found\n")
        f.write("\n******************************************\n\n")
        f.write("How much data is human readable?\n\n")
        percentPktSentReadable=getRatio(sentData.aboveThresh, sentData.dataPkts) * 100
        percentPktSentReadableAndZero=getRatio(sentData.aboveThreshwZeros, sentData.dataPkts) * 100
        percentPktSentHighEntropy=getRatio(sentData.highEntropy, sentData.dataPkts) * 100
        percentPktSentHighPval=getRatio(sentData.highPval, sentData.dataPkts) * 100
        percentPktSentHighCorr=getRatio(sentData.highCorr, sentData.dataPkts) * 100        
        f.write("Data from A -> B: \n")
        f.write("\t {} out of {} packets with >2 B of data have >{} printable characters\n".format(sentData.aboveThresh, sentData.dataPkts, "85%"))
        f.write("\t  - {}% of packets contain majority of printable characters \n".format(percentPktSentReadable))
        f.write("\t  - {}% of packets have high entropy \n".format(percentPktSentHighEntropy))
        f.write("\t  - {}% of packets have high P value from Chi2 test for uniform distribution \n".format(percentPktSentHighPval))
        f.write("\t  - {}% of packets have high self-correllation \n".format(percentPktSentHighCorr))
        f.write("\t {} out of {} packets with >2 B of data have >{} null & printable characters\n".format(sentData.aboveThreshwZeros, sentData.dataPkts, "85%"))
        f.write("\t  - {}% of packets \n".format(percentPktSentReadableAndZero))
        f.write("Data from B -> A: \n")
        percentPktRxReadable = getRatio(rxData.aboveThresh, rxData.dataPkts) * 100
        percentPktRxReadableAndZero = getRatio(rxData.aboveThreshwZeros, rxData.dataPkts) * 100
        percentPktRxHighEntropy=getRatio(rxData.highEntropy, rxData.dataPkts) * 100
        percentPktRxHighPval=getRatio(rxData.highPval, rxData.dataPkts) * 100
        percentPktRxHighCorr=getRatio(rxData.highCorr, rxData.dataPkts) * 100                
        f.write("\t {} out of {} packets with >2 B of data have >{} printable characters\n".format(rxData.aboveThresh, rxData.dataPkts, "85%"))
        f.write("\t  - {}% of packets \n".format(percentPktRxReadable))
        f.write("\t  - {}% of packets contain majority of printable characters \n".format(percentPktRxReadable))
        f.write("\t  - {}% of packets have high entropy \n".format(percentPktRxHighEntropy))
        f.write("\t  - {}% of packets have high P value from Chi2 test for uniform distribution \n".format(percentPktRxHighPval))
        f.write("\t {} out of {} packets with >2 B of data have >{} null & printable characters\n".format(rxData.aboveThreshwZeros, rxData.dataPkts, "85%"))
        f.write("\t  - {}% of packets \n".format(percentPktRxReadableAndZero))        
        if codeData.gCount>0 or codeData.mCount>0:
            f.write("\nFound G and/or M codes in ASCII\n")
            f.write(" - G-codes found: {}\n".format(codeData.gCount))
            for i in codeData.gDict:
                f.write("    {}x {}\n".format(codeData.gDict[i], i))
            f.write(" - M-codes found: {}\n".format(codeData.mCount))
            for i in codeData.mDict:
                f.write("    {}x {}".format(codeData.mDict[i].count, i))
                if codeData.mDict[i].count > 3:
                    avgInterval=getAvgInterval(codeData.mDict[i].times)
                    f.write(" {} Hz\n".format((1/avgInterval)))
                else:
                    f.write("\n")
        if(sentData.numPics>0 or rxData.numPics>0):
            f.write("\nFound Picture Files\n")
            if(sentData.numPics>0):
                f.write(" - {}x picture files of types: {}".format(sentData.numPics, sentData.picTypes))
            if(rxData.numPics>0):
                f.write(" - {}x picture files of types: {}".format(rxData.numPics, rxData.picTypes))
            f.write("\n")
        if(sentData.gzips>0 or rxData.gzips>0):
            f.write("\nFound Compressed Files\n")
            if(sentData.gzips>0):
                f.write(" - {}x gzip files sent".format(sentData.gzips))
            if(rxData.gzips>0):
                f.write(" - {}x gzip files received".format(rxData.gzips))
            f.write("\n")
        f.write("\n******************************************\n\n")
        f.write("What protocols are being used?\n\n")
        f.write("\t - Number of packets with HTTP protocol found: {}\n".format(protocolData.httpCount))
        if protocolData.httpCount > 0:
            f.write("\t     HTTP URIs \n")
            for i in protocolData.httpDict:
                f.write("\t\t * {}x {}\n".format(protocolData.httpDict[i],i))
        f.write("\t - Number of packets with FTTP protocol found: {}\n".format(protocolData.ftpCount))
        if protocolData.ftpCount > 0:
            f.write("\t     FTP URIs \n")
            for i in protocolData.ftpDict:
                f.write("\t\t * {}x {}\n".format(protocolData.ftpDict[i], i))
        f.write("\t - Number of packets with NET.TCP protocol found: {}\n".format(protocolData.nettcpCount))
        if protocolData.nettcpCount > 0:
            f.write("\t     NET.TCP URIs \n")
            for i in protocolData.nettcpDict:
                f.write("\t\t * {}x {}\n".format(protocolData.nettcpDict[i], i))
        if protocolData.httpCount==0 and protocolData.ftpCount==0 and protocolData.nettcpCount == 0:
            f.write("\nMost likely data is being sent over a raw TCP socket\n")

        f.write("\n******************************************\n\n")
        f.write("Note about the first couple of packets after the TCP handshake:\n\n")
        
    f.close()


    
def run(pcapData, hostData, targetIP, output):

    print("1) Running tests on the input pcap")

    encryptThresh=0.85

    broadcastData=check4Broadcasts(pcapData, hostData)

    sentData, rxData = findEncrypt(pcapData, hostData, targetIP, encryptThresh)

    protocolData = findComm(pcapData, hostData)

    codeData = findGCode(pcapData, hostData)

    firstPkts=findTCPstart(pcapData, hostData)

    checkInitPkts(firstPkts)

    writeLog(output, hostData, sentData, rxData, protocolData, broadcastData, codeData)
    

