import json
import os
import re
import csv
import sys
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler

# fileMal = "/home/manikant/Documents/CS698/midterm/parser/dynamic/virus_0b5e1d76c90b5a9a16e9bd843483a8157620d111ed4694ae128c57ea8868f738.json"
# fileBe = "/home/manikant/Documents/CS698/midterm/parser/dynamic/benign_0a0ee0aa381260d43987e98dd1a6f4bab11164e876f21db6ddb1db7c319c5cf8.json"

#directory = "/home/manikant/Documents/CS698/midterm/Dynamic_Analysis_RAWDATA/Malware/Virus"
#commonPath = "/home/manikant/Documents/CS698/midterm/Dynamic_Analysis_RAWDATA/"

count =0
namearr = []

resultFields = {"File_Hash","Predicted_Label"}

features = {
"name":0,
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
api = {'adjusttokenprivileges': 0, 'allocateandinitializesi': 0, 'certgetcertificatecontextproperty': 0, 'changeserviceconfigw': 0, 'charnextw': 0, 'checkdlgbutton': 0, 'checktokenmembership': 0, 'closehandle': 0, 'closeservicehandle': 0, 'clsidfromprogid': 0, 'cocreategui': 0, 'cocreateinstance': 0, 'coinitialize': 0, 'coinitializeex': 0, 'coinitializesecurity': 0, 'commandlinetoargvw': 0, 'comparestringa': 0, 'comparestringw': 0, 'connect': 0, 'connectnamedpipe': 0, 'controlservice': 0, 'convertstringsecuritydescriptortosecuritydescriptorw': 0, 'copyfileexw': 0, 'copyfilew': 0, 'cotaskmemalloc': 0, 'cotaskmemfree': 0, 'cotaskmemrealloc': 0, 'couninitialize': 0, 'createcompatibledc': 0, 'createdialogparamw': 0, 'createdirectoryw': 0, 'createeventw': 0, 'createfilea': 0, 'createfilemappingw': 0, 'createfilew': 0, 'createfontw': 0, 'createmutex': 0, 'createmutexw': 0, 'createnamedpipew': 0, 'createprocess': 0, 'createprocessw': 0, 'createremotethread': 0, 'createservice': 0, 'createthrea': 0, 'createtoolhelp32snapshot': 0, 'createwellknownsi': 0, 'createwindowexw': 0, 'cryptacquirecontext': 0, 'cryptacquirecontextw': 0, 'cryptcatadmincalchashfromfilehandle': 0, 'cryptcreatehash': 0, 'cryptdestroyhash': 0, 'cryptgethashparam': 0, 'crypthashdata': 0, 'crypthashpublickeyinfo': 0, 'cryptreleasecontext': 0, 'decodepointer': 0, 'decryptfilew': 0, 'defwindowprocw': 0, 'deletecriticalsection': 0, 'deletedc': 0, 'deletefilew': 0, 'deleteobject': 0, 'destroywindow': 0, 'deviceiocontrol': 0, 'dialogboxparamw': 0, 'dispatchmessagew': 0, 'exitprocess': 0, 'getprocaddress': 0, 'loadlibrarya': 0, 'dllinstall': 0, 'dosdatetimetofiletime': 0, 'duplicatehandle': 0, 'enablewindow': 0, 'encodepointer': 0, 'enddialog': 0, 'entercriticalsection': 0, 'enumprocesses': 0, 'enumprocessmodules': 0, 'enumsystemlocalesa': 0, 'expandenvironmentstringsw': 0, 'extracticonexw': 0, 'filetimetodosdatetime': 0, 'filetimetolocalfiletime': 0, 'filetimetosystemtime': 0, 'findclose': 0, 'findfirstfile': 0, 'findfirstfileexw': 0, 'findfirstfilew': 0, 'findnextfile': 0, 'findnextfilew': 0, 'findresource': 0, 'findresourceexw': 0, 'findresourcew': 0, 'flushfilebuffers': 0, 'flushinstructioncache': 0, 'formatmessagew': 0, 'freeenvironmentstringsw': 0, 'freelibrary': 0, 'getacp': 0, 'getactivewindow': 0, 'getadaptersinfo': 0, 'getasynckeystate': 0, 'getclientrect': 0, 'getcommandlinea': 0, 'getcommandlinew': 0, 'getcomputernamew': 0, 'getconsolecp': 0, 'getconsolemode': 0, 'getcpinfo': 0, 'getcurrentdirectoryw': 0, 'getcurrentprocess': 0, 'getcurrentprocessi': 0, 'getcurrentthreadi': 0, 'getcursorpos': 0, 'getdateformatw': 0, 'getdlgitem': 0, 'getenvironmentstringsw': 0, 'getexitcodeprocess': 0, 'getexitcodethrea': 0, 'getfileattributesexw': 0, 'getfileattributesw': 0, 'getfileinformationbyhandle': 0, 'getfilesize': 0, 'getfilesizeex': 0, 'getfiletime': 0, 'getfiletype': 0, 'getfileversioninfosizew': 0, 'getfileversioninfow': 0, 'getforegroundwindow': 0, 'getfullpathnamew': 0, 'getguiresources': 0, 'gethostbyname': 0, 'gethostname': 0, 'getkeyboardtype': 0, 'getlasterror': 0, 'getlocaleinfoa': 0, 'getlocaleinfow': 0, 'getlocaltime': 0, 'getmessagew': 0, 'getmodulefilenamew': 0, 'getmodulehandlea': 0, 'getmodulehandleexw': 0, 'getmodulehandlew': 0, 'getmonitorinfow': 0, 'getnativesysteminfo': 0, 'getobjectw': 0, 'getoemcp': 0, 'getparent': 0, 'getprivateprofileintw': 0, 'getprivateprofilestringw': 0, 'getprocessheap': 0, 'getprocessi': 0, 'getstartupinfow': 0, 'getstdhandle': 0, 'getstockobject': 0, 'getstringtypew': 0, 'getsystemdefaultlangid': 0, 'getsystemdefaultlcid': 0, 'getsystemdirectoryw': 0, 'getsystemtime': 0, 'getsystemtimeasfiletime': 0, 'getsystemtimes': 0, 'getsystemwow64directoryw': 0, 'gettempfilenamew': 0, 'gettemppathw': 0, 'getthreadlocale': 0, 'gettickcount': 0, 'gettimezoneinformation': 0, 'gettokeninformation': 0, 'getuserdefaultlangid': 0, 'getuserdefaultlcid': 0, 'getusernamew': 0, 'getversionexw': 0, 'getvolumepathnamew': 0, 'getwindow': 0, 'getwindowlongw': 0, 'getwindowrect': 0, 'getwindowsdirectory': 0, 'getwindowsdirectoryw': 0, 'getwindowtextlengthw': 0, 'getwindowtextw': 0, 'globalalloc': 0, 'globalfree': 0, 'globalmemorystatusex': 0, 'heapalloc': 0, 'heapcreate': 0, 'heapdestroy': 0, 'heapfree': 0, 'heaprealloc': 0, 'heapsetinformation': 0, 'heapsize': 0, 'httpaddrequestheadersw': 0, 'httpopenrequestw': 0, 'httpqueryinfow': 0, 'httpsendrequestw': 0, 'inet_addr': 0, 'initcommoncontrolsex': 0, 'initializeac': 0, 'initializecriticalsection': 0, 'initializecriticalsectionandspincount': 0, 'initializesecuritydescriptor': 0, 'initializeslisthea': 0, 'initiatesystemshutdownexw': 0, 'interlockedcompareexchange': 0, 'interlockeddecrement': 0, 'interlockedexchange': 0, 'interlockedincrement': 0, 'interlockedpopentryslist': 0, 'interlockedpushentryslist': 0, 'internetclosehandle': 0, 'internetconnectw': 0, 'internetcrackurlw': 0, 'interneterrordlg': 0, 'internetopenurl': 0, 'internetopenw': 0, 'internetreadfile': 0, 'internetsetoptionw': 0, 'isdebuggerpresent': 0, 'isdialogmessagew': 0, 'isdlgbuttonchecke': 0, 'isprocessorfeaturepresent': 0, 'isvalidcodepage': 0, 'isvalidlocale': 0, 'iswindow': 0, 'lcmapstringw': 0, 'ldrgetprocedureaddress': 0, 'ldrloaddll': 0, 'leavecriticalsection': 0, 'loadbitmapw': 0, 'loadcursorw': 0, 'loadiconw': 0, 'loadlibrary': 0, 'loadlibraryexw': 0, 'loadlibraryw': 0, 'loadresource': 0, 'localfiletimetofiletime': 0, 'localfree': 0, 'lockresource': 0, 'lookupprivilegevaluew': 0, 'mapviewoffile': 0, 'mapviewoffileex': 0, 'mapwindowpoints': 0, 'messageboxw': 0, 'minidumpreaddumpstream': 0, 'minidumpwritedump': 0, 'monitorfrompoint': 0, 'monitorfromwindow': 0, 'movefileexw': 0, 'msgwaitformultipleobjects': 0, 'multibytetowidechar': 0, 'openeventw': 0, 'openmutex': 0, 'openprocess': 0, 'openprocesstoken': 0, 'openscmanagerw': 0, 'openservicew': 0, 'ordina': 0, 'pathaddbackslashw': 0, 'pathappendw': 0, 'pathcanonicalizew': 0, 'pathfileexistsw': 0, 'pathfindextensionw': 0, 'pathisrelativew': 0, 'pathremovebackslashw': 0, 'pathremovefilespecw': 0, 'pathstrippathw': 0, 'peekmessagew': 0, 'postmessagew': 0, 'postquitmessage': 0, 'postthreadmessagew': 0, 'process32first': 0, 'process32next': 0, 'processidtosessioni': 0, 'queryperformancecounter': 0, 'queryserviceconfigw': 0, 'queryservicestatus': 0, 'queueuserapc': 0, 'raiseexception': 0, 'readfile': 0, 'recv': 0, 'regclosekey': 0, 'regcreatekeyexw': 0, 'regdeletekeya': 0, 'regdeletekeyw': 0, 'regdeletevaluew': 0, 'regenumkeyexw': 0, 'regenumvaluew': 0, 'registerclassw': 0, 'regopenkeyexw': 0, 'regqueryinfokeyw': 0, 'regqueryvalueexa': 0, 'regqueryvalueexw': 0, 'regsetvalueexw': 0, 'releasecapture': 0, 'releasemutex': 0, 'removedirectoryw': 0, 'resetevent': 0, 'rtlunwin': 0, 'selectobject': 0, 'send': 0, 'sendmessagew': 0, 'setactivewindow': 0, 'setcapture': 0, 'setcurrentdirectoryw': 0, 'setdlgitemtextw': 0, 'setendoffile': 0, 'setentriesinacla': 0, 'setentriesinaclw': 0, 'setenvironmentvariablea': 0, 'setenvironmentvariablew': 0, 'setevent': 0, 'setfileattributesw': 0, 'setfilepointer': 0, 'setfilepointerex': 0, 'setfiletime': 0, 'setfocus': 0, 'sethandlecount': 0, 'setlasterror': 0, 'setnamedpipehandlestate': 0, 'setnamedsecurityinfow': 0, 'setsecuritydescriptordac': 0, 'setsecuritydescriptorgroup': 0, 'setsecuritydescriptorowner': 0, 'setstdhandle': 0, 'setthreadexecutionstate': 0, 'settimer': 0, 'setunhandledexceptionfilter': 0, 'setwindowlongw': 0, 'setwindowpos': 0, 'setwindowtextw': 0, 'shcreatedirectoryexw': 0, 'shellexecute': 0, 'shellexecutea': 0, 'shellexecuteexw': 0, 'shfileoperationw': 0, 'shgetfolderpathw': 0, 'shgetspecialfolderpatha': 0, 'showwindow': 0, 'sizeofresource': 0, 'sleep': 0, 'startservicectrldispatcher': 0, 'strcmpiw': 0, 'strcpynw': 0, 'strcpyw': 0, 'stretchblt': 0, 'stringfromguid2': 0, 'strlena': 0, 'strlenw': 0, 'sysallocstring': 0, 'sysfreestring': 0, 'systemfunction036': 0, 'systemtimetofiletime': 0, 'systemtimetotzspecificlocaltime': 0, 'terminateprocess': 0, 'tlsalloc': 0, 'tlsfree': 0, 'tlsgetvalue': 0, 'tlssetvalue': 0, 'translatemessage': 0, 'unhandledexceptionfilter': 0, 'unmapviewoffile': 0, 'unregisterclassa': 0, 'unregisterclassw': 0, 'updatewindow': 0, 'uuidcreate': 0, 'variantclear': 0, 'variantinit': 0, 'varui4fromstr': 0, 'verifyversioninfow': 0, 'verqueryvaluew': 0, 'versetconditionmask': 0, 'virtualalloc': 0, 'virtualallocex': 0, 'virtualfree': 0, 'virtualprotectex': 0, 'waitforinputidle': 0, 'waitformultipleobjects': 0, 'waitforsingleobject': 0, 'widechartomultibyte': 0, 'winexec': 0, 'winverifytrust': 0, 'wlxloggedonsas': 0, 'writeconsolew': 0, 'writefile': 0, 'writeprocessmemory': 0, 'wsastartup': 0, 'wthelpergetprovsignerfromchain': 0, 'wthelperprovdatafromstatedata': 0}
features.update(api)
Arr = []

def writeHeader():
    with open('./TestData.csv', 'w', newline='') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=features)
        writer.writeheader()

def writeCSV(rows):
    with open('./TestData.csv', 'a', newline='') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=features)
        writer.writerow(rows)

def writeResultCSV(rows):
   rows.to_csv("./dynamic.csv",sep=",",encoding="utf-8", index=False)


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


def startProcessing(directory):
    for filename in os.listdir(directory)[:10]:
        if filename.endswith(".json"):
            namearr.append(filename.strip(".json"))
            print("extracting: " + filename)
            with open(os.path.join(directory, filename)) as json_file:
                data = json.load(json_file)
                #reset keys values for next file
                features.update({}.fromkeys(features,0))
                #write file name
                features.update({"name":filename.strip(".json")})
                #checkVirusTotalDetection(data)
                signatureAnalysis(data)
                apiStatAnalysis(data)
                summaryAnalysis(data)
                networkAnalysis(data)
                checkForCompressedFile(data)
            #print("extraction done: " + filename)
            Arr.append(features.copy())

def testWithModel():
    model = pickle.load(open("./scriptedDynamicModel.sav", "rb"))
    modelTree = pickle.load(open("./scriptedDynamicModelTree.sav", "rb"))
    df = pd.read_csv("./TestData.csv", sep=",")

    df = df.loc[(df != 0).any(axis=1)]
    df = df.fillna(0)
    df = df.drop(['name'], axis=1)
    X_t = df

    # scaler = StandardScaler()
    # scaler.fit(X_t)
    # scaler.transform(X_t)
    # pca_reload = pickle.load(open("./dynamicOutput/pca.pkl", 'rb'))
    # X_t = pca_reload.transform(X_t)

    yhat = model.predict(X_t)
    yhatTree = modelTree.predict(X_t)
    result = pd.DataFrame({'File_Hash': namearr, 'Predicted_Label': yhat})
    writeResultCSV(result)
    print(result)

def main():
    if len(sys.argv) < 2:
        print("Usage: dynamic.py <absolute_path> to files directory")
        sys.exit(0)
    else:
        PATH = sys.argv[1]
        print("PATH: ", PATH)
        startProcessing(PATH)
        writeHeader()
        for el in Arr:
            writeCSV(el)

if __name__ == '__main__':
    main()
    print("*****************************")
    print("****Extraction Completed*****")
    print("*****************************")
    print("*****Predicting Category*****")
    testWithModel()
    print("\nProcess Completed: output dynamic.csv")
    print("\nPath Analyzed: ", sys.argv[1])
