#!/usr/bin/env

import argparse
import re
import shlex
import subprocess
from os.path import isfile,isdir,join
from os import listdir, mkdir, chdir
from shutil import rmtree
import csv


def fileOrDir(fd):
    if isfile(fd):
        return "file"
    elif isdir(fd):
        return "dir"
    else:
        return "error"

def getFileList(fd):
    fileList=[]
    determineFileOrDir=fileOrDir(fd)
    if re.match('file', determineFileOrDir):
        fileList.append(fd)
    elif re.match('dir', determineFileOrDir):
        for f in listdir(fd):
            if isfile(join(fd,f)):
                if f.endswith('.P'):
                    fileList.append(join(fd,f))
    return fileList
    

def genGraph(rules, inputFile, goal=None):
    mkdir('tmp')
    chdir('tmp')
    if goal==None:
        cmd='graph_gen.sh -r ../{} -l ../{}'
        cmd=cmd.format(rules, inputFile)
    else:
        cmd='graph_gen.sh -r ../{} -l -g {} ../{}'
        cmd=cmd.format(rules, goal, inputFile)
    subprocess.call(shlex.split(cmd))

class Results:
    def __init__(self,dataExfil=0, defects=0, dos=0):
        self.dataExfil=dataExfil
        self.defects=defects
        self.dos=dos

    def reset(self):
        self.dataExfil=0
        self.defects=0
        self.dos=0

class Vuln:
    def __init__(self, location=0, multiplier=1):
        self.location=location
        self.multiplier=multiplier
        
class DataVals:
    def __init__(self, printer='', printMult=1, attacker='', atkMult=1):
        self.printer=printer
        self.printMult=printMult
        self.attacker=attacker
        self.atkMult=atkMult
        
class ResultsSearch:
    def __init__(self):
        self.dataExfil=[]
        self.defects=[]
        self.dos=[]
        self.printerMultiplier=[]
        self.printerList=[]

    def addPrinter(self, printerName):
        self.printerList.append(printerName)
        self.dataExfil.append({})
        self.defects.append({})
        self.dos.append({})
        self.printerMultiplier.append(getMultiplier(printerName))
        
    def getIndex(self, printerName):
        if printerName not in self.printerList:
            self.addPrinter(printerName)
        index=self.printerList.index(printerName)
        return index

    def reset(self):
        self.dataExfil=[]
        self.defects=[]
        self.dos=[]
        self.printerMultiplier=[]
        self.printerList=[]

def getVulnData(entry):
    results=DataVals()
    data=entry.split('(')[1]
    names=data.split(',')
    results.printer=names[0]
    results.printMult=getMultiplier(results.printer)
    results.attacker=names[1].split(')')[0]
    if re.search('switch', results.attacker) or re.search('wiFi', results.attacker):
        results.atkMult=1
    else:
        results.atkMult=getMultiplier(results.attacker)
    return results

def getMultiplier(value):
    num=re.search(r'\d+$', value)
    return int(num.group()) if num else 1
        
def collectResults(findings):
    searcher=ResultsSearch()
    if isfile('VERTICES.CSV') and isfile('ARCS.CSV'):
        with open('VERTICES.CSV') as f:
            verticesFile=csv.reader(f)
            for line in verticesFile:
                if 'vulnerableTo' in line[1]:
                    values=getVulnData(line[1])
                    index=searcher.getIndex(values.printer)
                    if re.search('ToDataExfiltration', line[1]):
                        searcher.dataExfil[index][values.attacker]=Vuln(line[0], values.atkMult)
                    elif re.search('ToMakingDefectiveParts', line[1]):
                        searcher.defects[index][values.attacker]=Vuln(line[0], values.atkMult)
                    elif re.search('ToDoS',line[1]):
                        searcher.dos[index][values.attacker]=Vuln(line[0], values.atkMult)
        with open('ARCS.CSV') as f:
            arcsFile=csv.reader(f)
            for line in arcsFile:
                for i in range(len(searcher.printerList)):
                    for src in searcher.dataExfil[i]:
                        if line[0]==searcher.dataExfil[i][src].location:
                            findings.dataExfil+=searcher.printerMultiplier[i]*searcher.dataExfil[i][src].multiplier
                    for src in searcher.defects[i]:
                        if line[0]==searcher.defects[i][src].location:
                            findings.defects+=searcher.printerMultiplier[i]*searcher.defects[i][src].multiplier
                    for src in searcher.dos[i]:
                        if line[0]==searcher.dos[i][src].location:
                            findings.dos+=searcher.printerMultiplier[i]*searcher.dos[i][src].multiplier

                        
def cleanUp():
    chdir('..')
    rmtree('tmp')

def check4tmp():
    if isdir('tmp'):
        rmtree('tmp')
    
def printResults(results, fileName):
    print('*****************************************************')
    print('Attack Graph Results for: {}'.format(fileName))
    print('Data Exfil: {}'.format(results.dataExfil))
    print('Defects   : {}'.format(results.defects))
    print('DoS       : {}'.format(results.dos))
    print('-----------------------------------------------------')
    
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input', '-i', required=True, type=str)
    parser.add_argument('--rules', '-r', required=True, type=str)
    parser.add_argument('--goals', '-g', required=False, type=str)
    args=parser.parse_args()

    check4tmp()
    
    goalList=[]
    if args.goals!=None:
        with open(args.goals) as f:
            data=f.readlines()
            for line in data:
                goalList.append(line.strip('\n'))
    
    cumResults=Results()
    fileList=getFileList(args.input)

    for inFile in fileList:
        print(inFile)
        if args.goals==None:
            genGraph(args.rules, inFile)
            collectResults(cumResults)
            cleanUp()
        else:
            for goal in goalList:
                genGraph(args.rules, inFile, goal)
                collectResults(cumResults)
                cleanUp()
        printResults(cumResults, inFile)
        cumResults.reset()
            


if __name__=='__main__':
    main()
