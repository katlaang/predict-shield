"""Show the format of the small open derived files (CC0): first lines and line counts."""
import urllib.request

UA = {"User-Agent": "predict-shield-research/1.0 (dataset format check)"}
for fid, name in ((3347727, "basket-3600"), (3347745, "browse-3600"), (3347741, "product-3600"), (3347747, "static-3600")):
    data = urllib.request.urlopen(urllib.request.Request(f"https://dataverse.harvard.edu/api/access/datafile/{fid}", headers=UA), timeout=60).read()
    lines = data.decode("utf-8", "replace").splitlines()
    print("FILE", name, "lines", len(lines))
    for l in lines[:4]:
        print("  ", l[:220])
