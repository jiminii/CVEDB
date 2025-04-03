## CVEDB
This is iotcube's version-based CVE detection tool.


## How to Use
Run the commands below from ***/CVEDB/***.
```
cd CVEDB/
```

### 1. DB generator
*DBGenerator* creates a database of CVE vulnerabilities for each version of each component from NVD. 

```
To be continue
```

### 2. Version mapping
*VersionMapping* maps dependent components and version information of the SBOM with the database. 

```
python3 ./src/VersionMapping.py
```

- Input & Output file name needs to be changed manually