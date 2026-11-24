"""Pin the PowerDuck archive and print its layout: member names and sizes,
any README, and the first records of one normal-operation IPAL file.
Attack-scenario contents are not printed."""
import gzip, hashlib, json, sys, zipfile

path = sys.argv[1]
data = open(path, "rb").read()
print("sha256", hashlib.sha256(data).hexdigest(), "bytes", len(data))
with zipfile.ZipFile(path) as z:
    names = [i for i in z.infolist() if not i.is_dir()]
    for i in names:
        print(f"{i.file_size:>12} {i.filename}")
    print("=====", "malicious/ index format (field names only)")
    for i in names:
        if "/malicious/" in i.filename:
            m = json.loads(gzip.decompress(z.read(i)))
            print(type(m).__name__, list(m)[:10] if isinstance(m, dict) else (type(m[0]).__name__ if m else "empty"))
            break
    for i in names:
        if i.filename.lower().split("/")[-1].startswith("readme") or i.filename.lower().endswith((".md", ".txt")):
            print("=====", i.filename)
            print(z.read(i).decode("utf-8", "replace")[:6000])
    normal = [i for i in names if "normal" in i.filename.lower() and not i.filename.lower().endswith((".pcap", ".pcapng"))]
    for i in normal[:2]:
        print("=====", i.filename, "(first records)")
        raw = z.read(i)
        text = (gzip.decompress(raw) if i.filename.endswith(".gz") else raw).decode("utf-8", "replace")
        print("records", len(text.splitlines()))
        for line in text.splitlines()[:3]:
            print(line[:1500])
