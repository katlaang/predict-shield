"""Per-message features for IEC 61850 GOOSE traffic in IPAL format (PowerDuck).

Each message is described relative to the previous message of its own
publication stream (same source and destination address) and to recent
traffic. Nothing here encodes what an attack looks like: these are the
quantities a GOOSE subscriber depends on (timing, state and sequence
numbers, frame length, the values carried), and the model learns their
normal joint behaviour from normal captures only.

Never inputs: the record id, the 'malicious' field, the capture file name,
absolute timestamps.
"""
from __future__ import annotations

import gzip
import json
import math
from collections import deque

import numpy as np

COUNTER_FIELDS = ("stNum", "sqNum")
WINDOW_S = 1.0
BASE_FEATURES = (
    "first_in_stream", "log_dt_stream_ms", "log_dt_any_ms",
    "stnum_delta", "stnum_decreased", "sqnum_delta", "sqnum_is_zero",
    "length", "length_delta", "data_fields", "field_set_changed",
    "numeric_fields", "log_mean_abs_value", "max_rel_change", "mean_rel_change", "text_fields_changed",
    "stream_msgs_last_1s", "all_msgs_last_1s",
)


def read_ipal(raw: bytes) -> list[dict]:
    """Records of one capture, gzip or plain, sorted by timestamp (stable)."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    records.sort(key=lambda r: float(r["timestamp"]))
    return records


def is_malicious(record: dict) -> bool:
    """IPAL marks attack messages with a truthy 'malicious' (an attack id or true)."""
    m = record.get("malicious")
    return m is not None and m is not False


def stream_of(record: dict) -> str:
    return f"{record.get('src')}>{record.get('dest')}"


def _split_data(data: dict):
    numeric, text = {}, {}
    for k, v in (data or {}).items():
        if k in COUNTER_FIELDS:
            continue
        if isinstance(v, bool):
            text[k] = str(v)
        elif isinstance(v, (int, float)):
            numeric[k] = float(v)
        else:
            text[k] = str(v)
    return numeric, text


def _clip(v: float, lo: float = -5.0, hi: float = 5.0) -> float:
    return max(lo, min(hi, v))


def capture_features(records: list[dict]) -> tuple[np.ndarray, list[str]]:
    """Feature rows (len(records) x len(BASE_FEATURES)) and the stream of each row."""
    rows, streams = [], []
    last: dict[str, dict] = {}
    recent_any: deque = deque()
    recent_stream: dict[str, deque] = {}
    prev_any_t = None
    for r in records:
        t = float(r["timestamp"])
        s = stream_of(r)
        data = r.get("data") or {}
        numeric, text = _split_data(data)
        st, sq = data.get("stNum"), data.get("sqNum")
        p = last.get(s)
        while recent_any and recent_any[0] < t - WINDOW_S:
            recent_any.popleft()
        q = recent_stream.setdefault(s, deque())
        while q and q[0] < t - WINDOW_S:
            q.popleft()
        dt_any = (t - prev_any_t) * 1000 if prev_any_t is not None else 0.0
        if p is None:
            f = [1.0, -1.0, math.log1p(max(dt_any, 0.0)), 0.0, 0.0, 0.0, float(sq == 0),
                 float(r.get("length") or 0), 0.0, float(len(data)), 0.0,
                 float(len(numeric)), math.log1p(np.mean([abs(v) for v in numeric.values()])) if numeric else 0.0,
                 0.0, 0.0, 0.0, float(len(q)), float(len(recent_any))]
        else:
            dst = (st - p["st"]) if isinstance(st, int) and isinstance(p["st"], int) else 0
            dsq = (sq - p["sq"]) if isinstance(sq, int) and isinstance(p["sq"], int) else 0
            rel = [abs(v - p["numeric"][k]) / (abs(p["numeric"][k]) + 1.0)
                   for k, v in numeric.items() if k in p["numeric"]]
            f = [0.0, math.log1p(max((t - p["t"]) * 1000, 0.0)), math.log1p(max(dt_any, 0.0)),
                 _clip(float(dst)), float(dst < 0), _clip(float(dsq)), float(sq == 0),
                 float(r.get("length") or 0), float((r.get("length") or 0) - p["length"]),
                 float(len(data)), float(set(data) != p["keys"]),
                 float(len(numeric)), math.log1p(np.mean([abs(v) for v in numeric.values()])) if numeric else 0.0,
                 math.log1p(max(rel)) if rel else 0.0, math.log1p(float(np.mean(rel))) if rel else 0.0,
                 float(sum(1 for k, v in text.items() if p["text"].get(k) != v)),
                 float(len(q)), float(len(recent_any))]
        rows.append(f)
        streams.append(s)
        last[s] = {"t": t, "st": st, "sq": sq, "length": r.get("length") or 0, "keys": set(data),
                   "numeric": numeric, "text": text}
        recent_any.append(t)
        q.append(t)
        prev_any_t = t
    return np.asarray(rows, dtype=np.float64).reshape(-1, len(BASE_FEATURES)), streams


def with_streams(x: np.ndarray, streams: list[str], known: list[str]) -> np.ndarray:
    """Append a one-hot of the stream among those seen in training, plus 'unseen'."""
    index = {s: i for i, s in enumerate(known)}
    onehot = np.zeros((len(streams), len(known) + 1))
    for row, s in enumerate(streams):
        onehot[row, index.get(s, len(known))] = 1.0
    return np.hstack([x, onehot])


def normal_threshold(scores, max_rate: float) -> float:
    s = np.sort(np.asarray(scores, dtype=np.float64))
    n = len(s)
    if n == 0:
        raise ValueError("no scores")
    allowed = int(math.floor(max_rate * n))
    return float(s[n - 1 - allowed]) if allowed < n else float(s[0])


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]
