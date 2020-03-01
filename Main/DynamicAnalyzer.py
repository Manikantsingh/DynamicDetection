import json
import os
import re
import csv
from Main.Section import api
fileMal = "/home/manikant/Documents/CS698/midterm/parser/dynamic/virus_0b5e1d76c90b5a9a16e9bd843483a8157620d111ed4694ae128c57ea8868f738.json"
fileBe = "/home/manikant/Documents/CS698/midterm/parser/dynamic/benign_0a0ee0aa381260d43987e98dd1a6f4bab11164e876f21db6ddb1db7c319c5cf8.json"

#directory = "/home/manikant/Documents/CS698/midterm/Dynamic_Analysis_RAWDATA/Malware/Virus"
commonPath = "/home/manikant/Documents/CS698/midterm/Dynamic_Analysis_RAWDATA/"
count =0

features = {
"category":0,
# "virustotal":0,
"network_icmp": 0,
"antivirus_virustotal": 0,
"antivm_queries_computername": 0,
"antivm_network_adapters": 0,

"file_created":0,
"directory_created":0,
"dll_loaded":0,
"file_written":0,
"command_line":0,
"regkey_opened":0,
"regkey_read":0,
"directory_enumerated":0,

"domains":0,
"dns":0,

"upx_compressed":0
}

features.update(api)
Arr = []

def writeHeader():
    with open('./dynamicTraningData.csv', 'w', newline='') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=features)
        writer.writeheader()

def writeCSV(rows):
    with open('./dynamicTraningData.csv', 'a', newline='') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=features)
        writer.writerow(rows)

def signatureAnalysis(data):
    sigItems = data.get("signatures")
    if(sigItems!=None):
        for sigItem in sigItems:
            keyName = sigItem.get("name")
            updateValue = {keyName: 1}
            if keyName=="antivm_queries_computername":
                features.update(updateValue)
            elif keyName=="antivirus_virustotal":
                features.update(updateValue)
            elif keyName=="antivm_network_adapters":
                features.update(updateValue)
            elif keyName=="network_icmp":
                features.update(updateValue)

def apiStatAnalysis(data):
    #keys = features.keys()
    apisCollection = data.get("behavior").get("apistats")
    for apis in apisCollection:
        for api in apisCollection.get(apis):
            if api.lower() in features.keys():
                value = apisCollection.get(apis).get(api)
                features.update({api.lower(): value})

def summaryAnalysis(data):
    behavior = data.get("behavior")
    if behavior!=None:
        summary = behavior.get("summary")
        if summary!=None:
            if summary.get("file_created")!=None:
                features.update({"file_created": len(summary.get("file_created"))})
            if summary.get("directory_created")!=None:
                features.update({"directory_created": len(summary.get("directory_created"))})
            if summary.get("dll_loaded")!=None:
                features.update({"dll_loaded": len(summary.get("dll_loaded"))})
            if summary.get("file_written")!=None:
                features.update({"file_written": len(summary.get("file_written"))})
            if summary.get("file_written")!=None:
                features.update({"file_written": len(summary.get("file_written"))})
            if summary.get("command_line")!=None:
                features.update({"command_line": len(summary.get("command_line"))})
            if summary.get("regkey_opened")!=None:
                features.update({"regkey_opened": len(summary.get("regkey_opened"))})
            if summary.get("regkey_read")!=None:
                features.update({"regkey_read": len(summary.get("regkey_read"))})
            if summary.get("directory_enumerated")!=None:
                features.update({"directory_enumerated": len(summary.get("directory_enumerated"))})


def checkVirusTotalDetection(data):
    if data.get("virustotal")!=None:
        detectedBy = data.get("virustotal").get("positives")
        if detectedBy!=None:
            features.update({"virustotal":detectedBy})


def networkAnalysis(data):
    network = data.get("network")
    if network != None:
        if network.get("domains") != None:
            features.update({"domains": len(network.get("domains"))})
        if network.get("dns") != None:
            features.update({"dns": len(network.get("dns"))})

def checkForCompressedFile(data):
    target = data.get("target")
    if target != None:
        file = target.get("file")
        if file !=None:
            type = file.get("type")
            if type != None:
                if "UPX" in type:
                    features.update({"upx_compressed": 1})


def extractBenignData():
    directory = commonPath + "Benign/"
    for filename in os.listdir(directory)[:10]:
        if filename.endswith(".json"):
            print("extracting: " + filename)
            with open(os.path.join(directory, filename)) as json_file:
                data = json.load(json_file)
                #reset keys values for next file
                features.update({}.fromkeys(features,0))
                #write file name
                features.update({"category":"B"})
                #checkVirusTotalDetection(data)
                signatureAnalysis(data)
                apiStatAnalysis(data)
                summaryAnalysis(data)
                networkAnalysis(data)
                checkForCompressedFile(data)
            print("extraction done: " + filename)
            writeCSV(features)

def extractMalwareData():
    directoryPath = commonPath + "Malware/"
    for file_folder in os.listdir(directoryPath)[:3]:
        for filename in os.listdir(directoryPath+file_folder):
            if filename.endswith(".json"):
                print("extracting: " + filename)
                with open(os.path.join(directoryPath, file_folder, filename)) as json_file:
                    data = json.load(json_file)

                    #reset keys values for next file
                    features.update({}.fromkeys(features,0))
                    #write file name
                    features.update({"category":"M"})
                    #checkVirusTotalDetection(data)
                    signatureAnalysis(data)
                    apiStatAnalysis(data)
                    summaryAnalysis(data)
                    networkAnalysis(data)
                    checkForCompressedFile(data)
                Arr.append(features.copy())


def main():
    extractMalwareData()
    extractBenignData()
    writeHeader()
    for el in Arr:
        writeCSV(el)
if __name__ == '__main__':
    main()
