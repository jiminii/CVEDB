import json
import re 
import os 

homePath = os.getcwd() ## /CVEDB/
DBPath = homePath + "/DB/Database.json"
InputPath = homePath + "/input/tensorflow-2.5.2.json" ## 파일명 변경 필요 
OutputPath = homePath + "/output/Result.json" ## 파일명 변경 필요 

if not os.path.isdir(homePath + "/output/"):
    os.mkdir(homePath + "/output/")

VersionOperation = {
    "versionEndIncluding" : (lambda x, y: x <= y),
    "versionEndExcluding" : (lambda x, y: x < y),
    "versionStartIncluding" : (lambda x, y: x >= y),
    "versionStartExcluding" : (lambda x, y: x > y)
}

def FilteringVersion(Ver):
    f_Ver = Ver.lower()
    f_Ver = re.sub(r"[^0-9a-z]", ".", f_Ver)
    return f_Ver

def MappingVersion(ResultList, DepComp, DepVer, DBData):
    CVEList = []
    
    f_DepComp = DepComp.lower()
    f_DepComp = re.sub(r"[^0-9a-z]", "", f_DepComp) ## luacjson
    if DepVer[0] == "v" or DepVer[0] == "V" or DepVer[0] == "r": 
        f_DepVer = DepVer[1:] ## 2.4-beta
    else: 
        f_DepVer = DepVer

    for DBDataComp in DBData:
        f_DBDataComp = DBDataComp.lower()
        f_DBDataComp = re.sub(r"[^0-9a-z]", "", f_DBDataComp)
        if f_DepComp == f_DBDataComp:            
            ## Version Mapping 
            if "versions" in DBData[DBDataComp]:
                for Ver in DBData[DBDataComp]["versions"]:
                    f_Ver = FilteringVersion(Ver)
                    ff_DepVer = FilteringVersion(f_DepVer)
                    
                    if f_Ver in ff_DepVer: 
                        CVEList.extend(DBData[DBDataComp]["versions"][Ver])
                        
            if "version_ranges" in DBData[DBDataComp]:
                for VerRanDict in DBData[DBDataComp]["version_ranges"]:
                    if len(VerRanDict) == 2: ## VersionRange 하나 있음 
                        Type, VerRan = list(VerRanDict.items())[0]
                        if Type in VersionOperation:
                            Operation = VersionOperation[Type]
                            f_VerRan = FilteringVersion(VerRan)
                            ff_DepVer = FilteringVersion(f_DepVer)
                            if Operation(ff_DepVer, f_VerRan):
                                CVEList.extend(VerRanDict["cve_ids"])      
                    elif len(VerRanDict) == 3: ## VersionRange 두개 있음 
                        Type1, VerRan1 = list(VerRanDict.items())[0]
                        Type2, VerRan2 = list(VerRanDict.items())[1]
                        if Type1 in VersionOperation and Type2 in VersionOperation:
                            Operation1 = VersionOperation[Type1]
                            Operation2 = VersionOperation[Type2]
                            f_VerRan1 = FilteringVersion(VerRan1)
                            f_VerRan2 = FilteringVersion(VerRan2)
                            ff_DepVer = FilteringVersion(f_DepVer)
                            if Operation1(ff_DepVer, f_VerRan1) and Operation2(ff_DepVer, f_VerRan2):
                                CVEList.extend(VerRanDict["cve_ids"])  
                    else:
                        print("Version Range Error") ## Version Range가 아예 없거나 2개 이상

    return CVEList


def Mapping(): 
    f1 = open(DBPath, 'r') 
    DBData = json.load(f1)
    
    ResultList = {}     
    f2 = open(InputPath, 'r')
    SBOMData = json.load(f2)
    
    SBOMComp = SBOMData["metadata"]["component"]["name"]
    if SBOMComp not in ResultList:
        ResultList[SBOMComp] = {}
    
    ## about dependent comp
    for DepList in SBOMData["dependencies"]:                
        for Data in DepList["dependsOn"]:
            DepComp = Data.split(" ")[0] ## lua-cjson
            DepVer = Data.split(" ")[1] ## v2.4-beta
            
            if DepComp not in ResultList[SBOMComp]:
                ResultList[SBOMComp][DepComp] = {}
            ResultList[SBOMComp][DepComp]["version"] = DepVer                
            
            ## Mapping 
            CVEList = MappingVersion(ResultList, DepComp, DepVer, DBData)
            CVEList = list(set(CVEList))
            ResultList[SBOMComp][DepComp]["CVE"] = CVEList
                
    SaveResult(ResultList)
    

def SaveResult(ResultList):
    with open(OutputPath, "w") as f:
        json.dump(ResultList, f, indent = 4)
    f.close()
    

def main():    
    Mapping()


if __name__ == "__main__":
	main()