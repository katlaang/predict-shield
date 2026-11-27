"""Print a Zenodo record's metadata (license, files, checksums, description). No data download."""
import html
import json
import re
import sys
import urllib.request

rec = json.load(urllib.request.urlopen(f"https://zenodo.org/api/records/{sys.argv[1]}", timeout=60))
md = rec.get("metadata", {})
print("TITLE:", md.get("title"))
print("VERSION:", md.get("version"), "| PUBLISHED:", md.get("publication_date"), "| DOI:", rec.get("doi"))
print("LICENSE:", md.get("license"))
print("CREATORS:", [(c.get("name"), c.get("affiliation")) for c in md.get("creators", [])])
for f in rec.get("files", []):
    print("FILE:", f.get("key"), f.get("size"), f.get("checksum"))
text = re.sub(r"<[^>]+>", "\n", html.unescape(md.get("description", "")))
text = re.sub(r"\n\s*\n+", "\n", text)
print("DESCRIPTION:\n" + text[:12000])
