#!/usr/bin/env python

# example call: python ../utils/inputJSON2P.py -i input-weak.JSON -o CyLabIoT-weak.P

import argparse
import json
import re

class AttackGraphInputs:
    def __init__(self, attackerLocation, attackerGoals,
                 networkData, properties, vulnerabilities):
        self.attackerLocation=attackerLocation
        self.attackerGoals=sorted(list(set(attackerGoals)))
        self.networkData=sorted(list(set(networkData)))
        self.properties=sorted(list(set(properties)))
        self.vulnerabilities=sorted(list(set(vulnerabilities)))

class Devices:
    def __init__(self, typesList, nameDict):
        self.typesList=typesList
        self.nameDict=nameDict

        
def getJSON(fd):
    with open(fd, 'r') as f:
        jsonData=json.load(f)
    f.close
    return jsonData

def getAllDevs(devDict):
    output=[]
    for category in list(devDict):
        for dev in devDict[category]:
            output.append(dev)
    return output

def getDevList(jsonData, dev):
    devs2Eval=jsonData[dev]
    if isinstance(devs2Eval, list):
        devDict={}
        devDict['all']=devs2Eval
        output=Devices(['all'], devDict)
    elif isinstance(devs2Eval, dict):
        typeList=list(devs2Eval)
        allDevs=getAllDevs(devs2Eval)
        devs2Eval['all']=allDevs
        output=Devices(typeList, devs2Eval)
    return output

def writeHaclEntry(item1, item2):
    output = []
    output.append('hacl('+item1+','+item2+',_,_).\n')
    output.append('hacl('+item2+','+item1+',_,_).\n')
    return output

def writeLocation(location):
    output = ''
    output = 'attackerLocated('+location+').\n'
    return output

def writeGoal(item, type2=None):
    output = []
    if type2==None:
        output.append('attackGoal(vulnerableToMakingDefectiveParts('+item+')).\n')
        output.append('attackGoal(vulnerableToDataExfiltration('+item+')).\n')
        output.append('attackGoal(vulnerableToDoS('+item+')).\n')
    else:
        output.append('attackGoal(vulnerableToMakingDefectiveParts('+item+',_)).\n')
        output.append('attackGoal(vulnerableToDataExfiltration('+item+',_)).\n')
        output.append('attackGoal(vulnerableToDoS('+item+',_)).\n')
    return output

def writeProperties(category, host, detailList=None):
    output=''
    if re.match('netSvc', category):
        output='networkServiceInfo('+host+',\''+detailList[0]+'\','+detailList[1]+','+detailList[2]+').\n'
    elif re.match('netDev', category) and detailList==None:
        output='networkHardware('+host+').\n'
    elif len(detailList)==2:
        output=detailList[0]+'('+host+',\''+detailList[1]+'\').\n'
    elif len(detailList)==4:
        output=detailList[0]+'('+host+','+detailList[1]+',\''+detailList[2]+'\',\''+detailList[3]+'\').\n'
    return output

def writeVuln(host, vulnList):
    output=[]
    output.append('vulExists('+host+',\''+vulnList[0]+'\',\''+vulnList[1]+'\').\n')
    output.append('vulProperty(\''+vulnList[0]+'\','+vulnList[2]+','+vulnList[3]+').\n')
    return output

def checkForNetPartition(entity):
    if entity == 'localNet':
        return True
    elif entity == 'internet':
        return True
    else:
        return False

def checkForAll(val):
    if val == 'all':
        return True
    else:
        return False

class DevClass:
    def __init__(self, devCats, printerData, controlPCData):
        self.devCats=devCats
        self.printerData=printerData
        self.controlPCData=controlPCData
        
    def inParamGroup(self, dev, param, group):
        if param == 'other':
            return True
        elif param == 'controlPCs':
            checkList=self.controlPCData.nameDict[group]
        elif param == 'printers':
            checkList=self.printerData.nameDict[group]
        if dev in checkList:
            return True
        else: return False
            
def processVulns(dev, vulnList, aggregateVulnList):
    vulns=writeVuln(dev,vulnList)
    for vuln in vulns:
        aggregateVulnList.append(vuln)

def processProps(dev, param, group, jsonData,
                 aggregateProperties, switchList=None,
                 listOfPrinters=None):
    for category in jsonData['properties'][param][group]:
        for itemList in jsonData['properties'][param][group][category]:
            if not checkForAll(dev):
                if re.match('all_printers',itemList[1]):
                    for printer in listOfPrinters:
                        aggregateProperties.append(itemList[0]+'('+dev+','+printer+',\''+itemList[2]+'\',\''+itemList[3]+'\').\n')
                else:
                    aggregateProperties.append(writeProperties(category,
                                                               dev, itemList))
            else:
                if param == 'switches':
                    for switchID in switchList:
                        aggregateProperties.append(writeProperties(category,
                                                                   switchID,
                                                                   itemList))

        
def parseJSON(jsonData, type2=None):
    params=jsonData['devCats']
    switchList=[]
    switchList=jsonData['switches']
    printerData=getDevList(jsonData, 'printers2Eval')
    printerList=getAllDevs(printerData.nameDict)
    controlPCData=getDevList(jsonData, 'controlPCs')
    controlPCList=getAllDevs(controlPCData.nameDict)
    devData=DevClass(params, printerData, controlPCData)
    topology={}
    topology=jsonData['topology']
    haclList=[]
    properties=[]
    vulnerabilities=[]
    for switch in (switchList+['all']):
        if 'switches' in jsonData['properties'] and switch in jsonData['properties']['switches']:
            processProps(switch, 'switches', switch, jsonData, properties, switchList)
        if 'switches' in jsonData['vulnerabilities'] and switch in jsonData['vulnerabilities']['switches']:
            for vulnList in jsonData['vulnerabilities']['switches'][switch]:
                if not checkForAll(switch):
                    processVulns(switch,vulnList,vulnerabilities)
                else:
                    for switchID in switchList:
                        processVulns(switchID,vulnList,vulnerabilities)
        if switch != 'all':
            properties.append(writeProperties('netDev', switch))
            for param in params:
                if param in topology[switch]:
                    for dev in topology[switch][param]:
                        haclEntries = writeHaclEntry(switch,dev)
                        for entry in haclEntries:
                            haclList.append(entry)
                        if param != 'other':
                            if param in jsonData['properties']:
                                for group in jsonData['properties'][param]:
                                    if devData.inParamGroup(dev,param,group):
                                        processProps(dev, param, group, jsonData, properties, listOfPrinters=printerList)
                            if param in jsonData['vulnerabilities']:
                                for group in jsonData['vulnerabilities'][param]:
                                    if devData.inParamGroup(dev,param,group):
                                        for vulnList in jsonData['vulnerabilities'][param][group]:
                                            processVulns(dev,vulnList, vulnerabilities)
                        if param == 'other':
                            if param in jsonData['properties'] and 'all' in jsonData['properties'][param]:
                                if not checkForNetPartition(dev):
                                    processProps(dev, param, 'all', jsonData, properties)
                            elif param in jsonData['properties'] and dev in jsonData['properties'][param]:
                                processProps(dev, param, dev, jsonData, properties)
                            if param in jsonData['vulnerabilities'] and 'all' in jsonData['vulnerabilities'][param]:
                                if not checkForNetPartition(dev):
                                    for vulnList in jsonData['vulnerabilities'][param]['all']:
                                        processVulns(dev, vulnList, vulnerabilities)
                            elif param in jsonData['vulnerabilities'] and dev in jsonData['vulnerabilities'][param]:
                                for vulnList in jsonData['vulnerabilities'][param][dev]:
                                    processVulns(dev,vulnList,vulnerabilities)

    attackGoals=[]
    attackerLocation=writeLocation(jsonData['location'])
    for printer in printerList:
        if type2==None:
            tempGoals=writeGoal(printer)
        else:
            tempGoals=writeGoal(printer, type2)
        for goal in tempGoals:
            attackGoals.append(goal)
    output=AttackGraphInputs(attackerLocation, attackGoals, haclList, properties, vulnerabilities)
    return output
    

def buildOutput(fileName, graphInputs):
    with open(fileName, 'w') as f:
        f.write(graphInputs.attackerLocation)
        f.write("\n")
        f.writelines(graphInputs.attackerGoals)
        f.write("\n")
        f.writelines(graphInputs.networkData)
        f.write("\n")
        f.writelines(graphInputs.properties)
        f.write("\n")
        f.writelines(graphInputs.vulnerabilities)
    f.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input', '-i', required=True, type=str)
    parser.add_argument('--output', '-o', required=False, type=str)
    parser.add_argument('--type2', default=False, action='store_true')
    args=parser.parse_args()

    if args.output==None:
        args.output='input.P'

    jsonData=getJSON(args.input)
    if args.type2==None:
        graphInputs=parseJSON(jsonData)
    else:
        graphInputs=parseJSON(jsonData, args.type2)

    buildOutput(args.output, graphInputs)

if __name__=='__main__':
    main()
