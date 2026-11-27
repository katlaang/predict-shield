"""Exploratory, after the single test: what makes up the alerts. Prints aggregate structure only
(site index, digit-normalized path, parameter names, user-agent family, value length), never values or addresses."""
import json
import pickle
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_logs as m  # noqa: E402


def agent_family(a: str) -> str:
    a = a.lower()
    for k in ("googlebot", "bingbot", "bot", "spider", "crawl", "curl", "python", "go-http", "wget", "okhttp",
              "android", "iphone", "chrome", "firefox", "safari", "mozilla"):
        if k in a:
            return k
    return "other" if a else "none"


models, zips = Path(sys.argv[1]), sys.argv[2:]
for zp in map(Path, zips):
    org = zp.stem
    b = pickle.loads((models / f"{org}.pkl").read_bytes())
    state, model = b["state"], b["model"]
    rows = [r for r in m.requests(zp) if r[1] >= m.SPLIT[org]]
    samples = [(m.template(s, mm, p), v) for s, t, mm, p, v, *_ in rows]
    raw = m.evidence(samples, state, model)
    cal, thr = np.asarray(state["calibration"]), state["thresholds"]
    fused = m.v3.fused(raw, cal, range(2)) > thr["fused"]
    forest = raw[:, 1] > thr["learned_anomaly"]
    seen = np.array([t in state["profiles"] for t, _ in samples])
    sites = {s: f"site-{i:02d}" for i, s in enumerate(sorted({r[0] for r in rows}))}

    def key(r):
        q = r[5].split("?", 1)[1]
        names = tuple(sorted({k for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True)}))[:5]
        return sites[r[0]], r[2], re.sub(r"[A-Za-z]", "a", r[3])[:40], names

    for label, mask in (("FUSED_ALERTS", fused), ("FUSED_SEEN", fused & seen), ("FUSED_UNSEEN", fused & ~seen),
                        ("FOREST_ALERTS", forest)):
        idx = np.flatnonzero(mask)
        print(org, label, len(idx))
        for k, c in Counter(key(rows[i]) for i in idx).most_common(8):
            print("   ", c, k)
        print("    agents", Counter(agent_family(rows[i][7]) for i in idx).most_common(6))
        lens = np.array([len(rows[i][4]) for i in idx]) if len(idx) else np.array([0])
        print("    input length median", int(np.median(lens)), "p90", int(np.percentile(lens, 90)))
    tr_len = np.array([len(v) for t, v in samples])
    print(org, "ALL test input length median", int(np.median(tr_len)), "p90", int(np.percentile(tr_len, 90)))
