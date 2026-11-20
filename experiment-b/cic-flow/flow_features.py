"""Features, labels and families for corrected CICFlowMeter flow records.

Shared by development (CIC-IDS2017 improved) and the single test run
(CSE-CIC-IDS2018 improved). Everything here is fixed in protocol.json before
any development result is looked at.

Three groups of model inputs:
  * flow statistics: every numeric CICFlowMeter column except identifiers,
    on a signed log scale, non-finite values set to 0
  * traffic type: protocol and a destination-service bucket from the
    destination port (the port value itself is not an input)
  * context: what the same source, and the same destination, did in the
    preceding 60 seconds, computed causally in file order

Never inputs: row id, Flow ID, IP addresses, source port, timestamp, label.
"""
from __future__ import annotations

import math
import re
from collections import Counter, deque
from datetime import datetime

import numpy as np

IDENTIFIERS = ("id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
               "Label", "Attempted Category")
SERVICE_PORTS = (20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
                 445, 465, 587, 993, 995, 1433, 3306, 3389, 5353, 5355, 8080, 8443)
PROTOCOLS = (6, 17, 1)
WINDOW_SECONDS = 60.0
CONTEXT_FEATURES = ("src_flows_60s", "src_distinct_dst_ports_60s", "src_distinct_dst_ips_60s",
                    "src_same_dst_port_fraction_60s", "dst_flows_60s", "dst_distinct_src_ips_60s")

# Attack families. A label's family is the first pattern that matches it,
# case-insensitively. Written before the test labels were read; a test label
# that matches nothing is reported as "unmapped".
FAMILY_PATTERNS = (
    ("heartbleed", r"heartbleed"),
    ("web-attack", r"web.?attack|xss|sql|brute.?force.?-?.?(web|xss)"),
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
    """(is_attack, family). Benign and '- Attempted' flows are benign, as the
    dataset authors recommend for flows that carried no attack behaviour."""
    text = (label or "").strip()
    if not text or text.upper() == "BENIGN" or re.search(r"attempted", text, re.I):
        return False, "benign"
    for family, pattern in FAMILY_PATTERNS:
        if re.search(pattern, text, re.I):
            return True, family
    return True, "unmapped"


def numeric_columns(header: list[str]) -> list[str]:
    return [c for c in header if c not in IDENTIFIERS]


def service_bucket(port) -> str:
    try:
        p = int(float(port))
    except (TypeError, ValueError):
        return "unknown"
    if p in SERVICE_PORTS:
        return f"port-{p}"
    return "ephemeral" if p >= 49152 else "registered" if p >= 1024 else "other-wellknown"


SERVICE_NAMES = tuple(f"port-{p}" for p in SERVICE_PORTS) + ("ephemeral", "registered", "other-wellknown",
                                                             "unknown")


def signed_log(values: np.ndarray) -> np.ndarray:
    values = np.where(np.isfinite(values), values, 0.0)
    return np.sign(values) * np.log1p(np.abs(values))


_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M")


def parse_time(text: str) -> float:
    text = str(text).strip()
    for fmt in _FORMATS:
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    raise ValueError(f"unrecognized timestamp {text!r}")


class ContextWindow:
    """Causal 60-second context. For each flow, counts only flows that came
    earlier in the same file, with a timestamp within the window before this
    flow's own. State carries across chunks of one file and is reset per file."""

    def __init__(self, window: float = WINDOW_SECONDS):
        self.window = window
        self.src: dict[str, deque] = {}
        self.src_ports: dict[str, Counter] = {}
        self.src_ips: dict[str, Counter] = {}
        self.dst: dict[str, deque] = {}
        self.dst_srcs: dict[str, Counter] = {}

    @staticmethod
    def _evict(q: deque, counters: tuple, now: float, window: float, fields: tuple) -> None:
        while q and q[0][0] < now - window:
            old = q.popleft()
            for counter, i in zip(counters, fields):
                k = old[i]
                counter[k] -= 1
                if not counter[k]:
                    del counter[k]

    def step(self, ts: float, src: str, dst: str, dport: str) -> tuple[float, ...]:
        q = self.src.setdefault(src, deque())
        ports = self.src_ports.setdefault(src, Counter())
        ips = self.src_ips.setdefault(src, Counter())
        self._evict(q, (ports, ips), ts, self.window, (1, 2))
        n = len(q)
        same = ports.get(dport, 0)
        out_src = (n, len(ports), len(ips), same / n if n else 0.0)
        dq = self.dst.setdefault(dst, deque())
        srcs = self.dst_srcs.setdefault(dst, Counter())
        self._evict(dq, (srcs,), ts, self.window, (1,))
        out_dst = (len(dq), len(srcs))
        q.append((ts, dport, dst))
        ports[dport] += 1
        ips[dst] += 1
        dq.append((ts, src))
        srcs[src] += 1
        return out_src + out_dst


def feature_names(numeric: list[str]) -> list[str]:
    return ([f"log:{c}" for c in numeric] + [f"proto:{p}" for p in PROTOCOLS] + ["proto:other"]
            + [f"svc:{s}" for s in SERVICE_NAMES] + [f"ctx:{c}" for c in CONTEXT_FEATURES])


def build(frame, numeric: list[str], context: ContextWindow) -> np.ndarray:
    """Model inputs for a pandas DataFrame chunk, in file order."""
    flows = signed_log(np.column_stack([_to_float(frame[c]) for c in numeric]) if numeric
                       else np.zeros((len(frame), 0)))
    proto = _to_float(frame["Protocol"], missing=-1.0)
    proto_cols = [(proto == p) for p in PROTOCOLS]
    proto_cols.append(~np.isin(proto, PROTOCOLS))
    svc = frame["Dst Port"].map(service_bucket).to_numpy()
    svc_cols = [(svc == s) for s in SERVICE_NAMES]
    times = [parse_time(t) for t in frame["Timestamp"].to_numpy()]
    ctx = np.array([context.step(t, str(s), str(d), str(p)) for t, s, d, p in
                    zip(times, frame["Src IP"].to_numpy(), frame["Dst IP"].to_numpy(),
                        frame["Dst Port"].to_numpy())], dtype=np.float64).reshape(len(frame), -1)
    ctx[:, [0, 1, 2, 4, 5]] = np.log1p(ctx[:, [0, 1, 2, 4, 5]])
    return np.hstack([flows, np.column_stack(proto_cols + svc_cols).astype(np.float64), ctx]).astype(np.float32)


def _to_float(series, missing: float = 0.0) -> np.ndarray:
    import pandas as pd
    return pd.to_numeric(series, errors="coerce").fillna(missing).to_numpy(dtype=np.float64)


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def benign_threshold(benign_scores: np.ndarray, max_rate: float) -> float:
    """Smallest cutoff t, among the observed scores, with the fraction of
    benign scores strictly above t at most max_rate. Alert when score > t."""
    s = np.sort(np.asarray(benign_scores, dtype=np.float64))
    n = len(s)
    if n == 0:
        raise ValueError("no benign calibration scores")
    allowed = int(math.floor(max_rate * n))
    return float(s[n - 1 - allowed]) if allowed < n else float(s[0])


def split_bucket(member: str, row_id) -> int:
    """Deterministic 0..9 bucket from the file name and row id."""
    import hashlib
    digest = hashlib.sha256(f"{member}\x00{row_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % 10
