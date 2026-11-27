"""Print a Harvard Dataverse dataset's license and file list with checksums. No data download."""
import json
import sys
import urllib.request

DOI = sys.argv[1]
url = f"https://dataverse.harvard.edu/api/datasets/:persistentId/?persistentId={DOI}"
d = json.load(urllib.request.urlopen(url, timeout=60))["data"]["latestVersion"]
print("VERSION", d.get("versionNumber"), d.get("versionMinorNumber"), d.get("releaseTime"))
print("LICENSE", json.dumps(d.get("license")), "TERMS", json.dumps(d.get("termsOfUse"))[:400])
for f in d.get("files", []):
    df = f["dataFile"]
    print("FILE", df["id"], df["filename"], df.get("filesize"), json.dumps(df.get("checksum")), df.get("contentType"),
          "restricted" if f.get("restricted") else "open")
for fld in d.get("metadataBlocks", {}).get("citation", {}).get("fields", []):
    if fld["typeName"] in ("title", "dsDescription", "timePeriodCovered", "dateOfCollection"):
        print("META", fld["typeName"], json.dumps(fld["value"])[:600])
