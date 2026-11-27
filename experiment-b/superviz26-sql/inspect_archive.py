"""List the Superviz26-SQL archive and count rows by split and label per file (no feature or label relationships)."""
import sys
import zipfile
from collections import Counter

import pandas as pd

with zipfile.ZipFile(sys.argv[1]) as z:
    infos = [i for i in z.infolist() if not i.is_dir()]
    for i in infos:
        print("MEMBER", i.filename, i.file_size)
    for i in infos:
        if not i.filename.endswith(".csv"):
            continue
        counts, templates, cols = Counter(), Counter(), None
        with z.open(i) as f:
            for chunk in pd.read_csv(f, chunksize=500_000, low_memory=False):
                cols = cols or list(chunk.columns)
                if "split" in chunk and "label" in chunk:
                    counts.update(zip(chunk["split"], chunk["label"]))
                if "query_template_id" in chunk:
                    templates.update(chunk.loc[chunk.get("split", "") == "train", "query_template_id"]
                                     if "split" in chunk else chunk["query_template_id"])
        print("CSV", i.filename, "columns", cols)
        print("    rows by (split,label):", dict(counts), "| train templates:", len(templates))
