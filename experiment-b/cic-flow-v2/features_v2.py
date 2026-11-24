"""Version 2 features, labels and calibration helpers for corrected
CICFlowMeter flow records. Fixed in protocol_v2.json before any v2 result.

Changes from version 1 (experiment-b/cic-flow), each answering a v1 finding:
  * no per-source context: the four per-source counts let the model learn
    which machine sent the traffic rather than what the traffic did
  * context is computed over flows sorted by timestamp, so "the preceding
    60 seconds" holds even when the file is out of order; the number of
    out-of-order rows is counted and reported
  * the remaining context is per destination: flows to this destination and
    distinct sources contacting it in the preceding 60 seconds

Model inputs: signed-log flow statistics (every non-identifier numeric
column), protocol, destination-service bucket, two per-destination context
counts. Never inputs: id, Flow ID, IP addresses, ports, timestamp, label.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, deque

import numpy as np
import pandas as pd

IDENTIFIERS = ("id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
               "Label", "Attempted Category")
SERVICE_PORTS = (20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
                 445, 465, 587, 993, 995, 1433, 3306, 3389, 5353, 5355, 8080, 8443)
SERVICE_NAMES = tuple(f"port-{p}" for p in SERVICE_PORTS) + ("ephemeral", "registered", "other-wellknown",
                                                             "unknown")
PROTOCOLS = (6, 17, 1)
WINDOW_SECONDS = 60.0
CONTEXT_FEATURES = ("dst_flows_60s", "dst_distinct_src_ips_60s")
CONTEXT_COLUMNS = ["Timestamp", "Src IP", "Dst IP"]

FAMILY_PATTERNS = (
    ("heartbleed", r"heartbleed"),
    ("web-attack", r"web.?attack|xss|sql"),
    ("infiltration", r"infil"),
    ("brute-force-ftp", r"ftp"),
    ("brute-force-ssh", r"ssh"),
    ("ddos", r"ddos|loic|hoic"),
    ("dos-slow", r"slowloris|slowhttp"),
    ("dos-hulk", r"hulk"),
    ("dos-goldeneye", r"goldeneye"),
    ("botnet", r"bot|ares|zeus"),
    ("portscan", r"port.?scan|nmap"),
)


def label_class(label: str) -> tuple[bool, str]:
    text = (label or "").strip()
    if not text or text.upper() == "BENIGN" or re.search(r"attempted", text, re.I):
        return False, "benign"
    for family, pattern in FAMILY_PATTERNS:
        if re.search(pattern, text, re.I):
            return True, family
    return True, "unmapped"


def numeric_columns(header: list[str]) -> list[str]:
    return [c for c in header if c not in IDENTIFIERS]


def feature_names(numeric: list[str]) -> list[str]:
    return ([f"log:{c}" for c in numeric] + [f"proto:{p}" for p in PROTOCOLS] + ["proto:other"]
            + [f"svc:{s}" for s in SERVICE_NAMES] + [f"ctx:{c}" for c in CONTEXT_FEATURES])


def service_bucket(port) -> str:
    try:
        p = int(float(port))
    except (TypeError, ValueError):
        return "unknown"
    if p in SERVICE_PORTS:
        return f"port-{p}"
    return "ephemeral" if p >= 49152 else "registered" if p >= 1024 else "other-wellknown"


def signed_log(values: np.ndarray) -> np.ndarray:
    values = np.where(np.isfinite(values), values, 0.0)
    return np.sign(values) * np.log1p(np.abs(values))


def to_float(series, missing: float = 0.0) -> np.ndarray:
    return pd.to_numeric(series, errors="coerce").fillna(missing).to_numpy(dtype=np.float64)


_FORMATS = ("ISO8601", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
            "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M")


def parse_times(series: pd.Series) -> np.ndarray:
    """Seconds as float64. One format must parse every value, else ValueError."""
    for fmt in _FORMATS:
        try:
            parsed = pd.to_datetime(series.astype(str).str.strip(), format=fmt)
        except (ValueError, TypeError):
            continue
        if parsed.isna().any():
            continue
        return parsed.astype("datetime64[us]").astype("int64").to_numpy() / 1e6
    raise ValueError(f"no single timestamp format parses this column (first value {series.iloc[0]!r})")


def destination_context(times: np.ndarray, srcs, dsts, window: float = WINDOW_SECONDS):
    """Per-destination context in time order. Returns (context in the input row
    order, number of rows whose timestamp is earlier than an earlier row's).
    For each flow: flows to the same destination, and distinct sources
    contacting it, among flows earlier in time order (ties broken by row
    order) and no more than `window` seconds older."""
    times = np.asarray(times, dtype=np.float64)
    n = len(times)
    out_of_order = int(np.sum(times[1:] < np.maximum.accumulate(times)[:-1])) if n > 1 else 0
    order = np.argsort(times, kind="stable")
    ctx = np.zeros((n, 2), dtype=np.float64)
    queues: dict = {}
    sources: dict = {}
    srcs = np.asarray(srcs, dtype=object)
    dsts = np.asarray(dsts, dtype=object)
    for i in order:
        t, s, d = times[i], srcs[i], dsts[i]
        q = queues.get(d)
        if q is None:
            q, c = queues[d], sources[d] = deque(), Counter()
        else:
            c = sources[d]
        while q and q[0][0] < t - window:
            _, old = q.popleft()
            c[old] -= 1
            if not c[old]:
                del c[old]
        ctx[i, 0], ctx[i, 1] = len(q), len(c)
        q.append((t, s))
        c[s] += 1
    return ctx, out_of_order


def build(frame: pd.DataFrame, numeric: list[str], ctx: np.ndarray) -> np.ndarray:
    """Model inputs for a chunk; ctx holds this chunk's context rows."""
    flows = signed_log(np.column_stack([to_float(frame[c]) for c in numeric]))
    proto = to_float(frame["Protocol"], missing=-1.0)
    proto_cols = [(proto == p) for p in PROTOCOLS] + [~np.isin(proto, PROTOCOLS)]
    svc = frame["Dst Port"].map(service_bucket).to_numpy()
    svc_cols = [(svc == s) for s in SERVICE_NAMES]
    return np.hstack([flows, np.column_stack(proto_cols + svc_cols).astype(np.float64),
                      np.log1p(ctx)]).astype(np.float32)


def benign_threshold(scores: np.ndarray, max_rate: float) -> float:
    """Smallest observed cutoff t with the share of scores strictly above t at
    most max_rate. Alert when score > t."""
    s = np.sort(np.asarray(scores, dtype=np.float64))
    n = len(s)
    if n == 0:
        raise ValueError("no calibration scores")
    allowed = int(math.floor(max_rate * n))
    return float(s[n - 1 - allowed]) if allowed < n else float(s[0])


def split_bucket(member: str, row_id) -> int:
    digest = hashlib.sha256(f"{member}\x00{row_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % 10


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def read_member(archive, member: str, chunksize: int = 200_000):
    """Two passes over one CSV member: context first, then chunks of rows with
    their context slice. Yields (chunk, ctx_chunk); returns stats via .stats."""
    import zipfile
    with zipfile.ZipFile(archive) as z:
        with z.open(member) as raw:
            head = pd.read_csv(raw, usecols=CONTEXT_COLUMNS, dtype=str, low_memory=False)
        times = parse_times(head["Timestamp"])
        ctx, out_of_order = destination_context(times, head["Src IP"].to_numpy(), head["Dst IP"].to_numpy())
        rows = len(head)
        del head
        stats = {"rows": rows, "out_of_order_rows": out_of_order}
        start = 0
        with z.open(member) as raw:
            for chunk in pd.read_csv(raw, chunksize=chunksize, low_memory=False):
                end = start + len(chunk)
                yield chunk, ctx[start:end], stats
                start = end
        if start != rows:
            raise ValueError(f"{member}: second pass read {start} rows, first pass {rows}")
