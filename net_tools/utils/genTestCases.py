#!/bin/env/python

import json
import argparse
import copy


def getBaselineData(filename):
    with open(filename, 'r') as f:
        data=json.load(f)
        f.close()
    return data

def writeNewJSON(folder,filename, data):
    path=folder+'/'+filename
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def updateJSONlist(data, category, device, group, newData):
    if category in data:
        if device in data[category]:
            if group in data[category][device]:
                data[category][device][group]+=[newData]
            else:
                data[category][device][group]=[newData]
        else:
            data[category][device]={group:[newData]}
    else:
        data={category:{group:[newData]}}
    return data

def updateJSONj(data, category, device, group, item, newData):
    if category in data:
        if device in data[category]:
            if group in data[category][device]:
                if item in data[category][device][group]:
                    data[category][device][group][item]+=[newData]
                else:
                    data[category][device][group][item]=[newData]
            else:
                data[category][device][group]={item:[newData]}
        else:
            data[category][device]={group:{item:[newData]}}
    else:
        data[category]={device:{group:{item:[newData]}}}
    return data

def PCbadLinks(data):
    data=updateJSONlist(data, 'vulnerabilities', 'controlPCs', 'all', ['maliciousLink', 'InternetExplorer', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'controlPCs', 'all', 'misc', ['installed', 'InternetExplorer'])
    return data

def PCusb(data):
    data=updateJSONlist(data, 'vulnerabilities', 'controlPCs', 'all', ['badUSB', 'AutoRun', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'controlPCs', 'all', 'misc', ['installed', 'AutoRun'])
    return data

def PColdSW(data):
    data=updateJSONlist(data, 'vulnerabilities', 'controlPCs', 'all', ['oldSW', 'win95', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'controlPCs', 'all', 'misc', ['installed', 'win95'])
    return data

def badSwitches(data):
    data=updateJSONlist(data, 'vulnerabilities', 'switches', 'all', ['rootkit', 'Cisco_IOS', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'switches', 'all', 'netSvc', ['Cisco_IOS', '_', '_'])
    data=updateJSONj(data, 'properties', 'switches', 'all', 'misc', ['progRunning', 'Cisco_IOS'])
    return data

def otherCreds(data):
    data=updateJSONlist(data, 'vulnerabilities', 'other', 'all', ['DefaultCredentials', 'Login', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'other', 'all', 'netSvc', ['Login', 'tcp', '80'])
    return data

def otherRCE(data):
    data=updateJSONlist(data, 'vulnerabilities', 'other', 'all', ['SambaCry', 'Samba', 'remoteExploit', 'privEscalation'])
    data=updateJSONj(data, 'properties', 'other', 'all', 'netSvc', ['Samba', 'tcp', '139'])
    return data

def generateTestCases(baselineData, folder):
    # Write file for no assumed vulns on other devices
    writeNewJSON(folder, 'input-clean.JSON', baselineData)

    # Write file(s) for PCs with malicious links
    case1=copy.deepcopy(baselineData)
    case1=PCbadLinks(case1)
    writeNewJSON(folder, 'input-PC_links.JSON', case1)

    case2=copy.deepcopy(case1)
    case2=badSwitches(case2)
    writeNewJSON(folder, 'input-PC_links_badSwitch.JSON', case2)

    case3=copy.deepcopy(case1)
    case3=otherCreds(case3)
    writeNewJSON(folder, 'input-PC_links_otherCreds.JSON', case3)

    case4=copy.deepcopy(case1)
    case4=otherRCE(case4)
    writeNewJSON(folder, 'input-PC_links_otherRCE.JSON', case4)

    case5=copy.deepcopy(baselineData)
    case5=PCusb(case5)
    writeNewJSON(folder, 'input-PC_usb.JSON', case5)

    case6=copy.deepcopy(case5)
    case6=badSwitches(case6)
    writeNewJSON(folder, 'input-PC_usb_badSwitch.JSON', case6)

    case7=copy.deepcopy(case5)
    case7=otherCreds(case7)
    writeNewJSON(folder, 'input-PC_usb_otherCreds.JSON', case7)

    case8=copy.deepcopy(case5)
    case8=otherRCE(case8)
    writeNewJSON(folder, 'input-PC_usb_otherRCE.JSON', case8)

    case9=copy.deepcopy(baselineData)
    case9=PColdSW(case9)
    writeNewJSON(folder, 'input-PC_oldSW.JSON', case5)

    case10=copy.deepcopy(case9)
    case10=badSwitches(case10)
    writeNewJSON(folder, 'input-PC_oldSW_badSwitch.JSON', case10)

    case11=copy.deepcopy(case9)
    case11=otherCreds(case11)
    writeNewJSON(folder, 'input-PC_oldSW_otherCreds.JSON', case11)

    case12=copy.deepcopy(case9)
    case12=otherRCE(case12)
    writeNewJSON(folder, 'input-PC_oldSW_otherRCE.JSON', case12)

    case13=copy.deepcopy(baselineData)
    case13=badSwitches(case13)
    writeNewJSON(folder, 'input-badSwitch.JSON', case13)

    case14=copy.deepcopy(baselineData)
    case14=otherCreds(case14)
    writeNewJSON(folder, 'input-otherCreds.JSON', case14)

    case15=copy.deepcopy(case14)
    case15=badSwitches(case15)
    writeNewJSON(folder, 'input-otherCreds_badSwitch.JSON', case15)

    case16=copy.deepcopy(baselineData)
    case16=otherRCE(case16)
    writeNewJSON(folder, 'input-otherRCE.JSON', case16)

    case17=copy.deepcopy(case16)
    case17=badSwitches(case17)
    writeNewJSON(folder, 'input-otherRCE_badSwitch.JSON', case17)

    case18=copy.deepcopy(baselineData)
    case18=PCbadLinks(case18)
    case18=PCusb(case18)
    case18=PColdSW(case18)
    case18=badSwitches(case18)
    case18=otherCreds(case18)
    case18=otherRCE(case18)
    writeNewJSON(folder, 'input-all.JSON', case18)

    
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--inputFile', '-i', required=True, type=str)
    parser.add_argument('--outputDir', '-o', required=True, type=str)
    args=parser.parse_args()

    baselineData=getBaselineData(args.inputFile)
    generateTestCases(baselineData, args.outputDir)

if __name__=='__main__':
    main()
