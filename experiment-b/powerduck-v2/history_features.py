"""Version 2 GOOSE features: each message compared with its stream's recent history.

Version 1 compared a message only with the previous message of its stream, so
once an attacker sustained a change, each new injected message looked normal.
Version 2 keeps the version 1 features and adds, per stream, comparisons with
the last HISTORY messages: how far timing, values, length and rate sit from
their recent median, and how often state and sequence numbers have jumped.
Nothing here encodes an attack; the model learns normal behaviour only.
"""
from __future__ import annotations

import math
import sys
from collections import deque
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "powerduck"))
import goose_features as gf  # noqa: E402

HISTORY = 20
HISTORY_FEATURES = (
    "dt_vs_history", "value_vs_history", "length_vs_history", "rate_vs_history",
    "stnum_jumps_in_history", "sqnum_breaks_in_history", "history_fill",
)


def _robust_z(value: float, past: list[float]) -> float:
    if not past:
        return 0.0
    med = float(np.median(past))
    mad = float(np.median([abs(p - med) for p in past]))
    return max(-20.0, min(20.0, (value - med) / (mad * 1.4826 + 1e-3)))


def capture_features(records: list[dict]) -> tuple[np.ndarray, list[str]]:
    base, streams = gf.capture_features(records)
    hist: dict[str, dict[str, deque]] = {}
    extra = []
    names = list(gf.BASE_FEATURES)
    i_dt, i_len = names.index("log_dt_stream_ms"), names.index("length")
    i_val, i_st = names.index("log_mean_abs_value"), names.index("stnum_delta")
    i_sq, i_rate = names.index("sqnum_delta"), names.index("stream_msgs_last_1s")
    i_first = names.index("first_in_stream")
    for row, s in zip(base, streams):
        h = hist.setdefault(s, {k: deque(maxlen=HISTORY) for k in ("dt", "val", "len", "rate", "st", "sq")})
        first = row[i_first] == 1.0
        dt, val, ln, rate = row[i_dt], row[i_val], row[i_len], row[i_rate]
        st_jump = float(row[i_st] != 0.0) if not first else 0.0
        sq_break = float(row[i_sq] != 1.0 and row[i_sq] != 0.0) if not first else 0.0
        extra.append([
            _robust_z(dt, list(h["dt"])) if not first else 0.0,
            _robust_z(val, list(h["val"])),
            _robust_z(ln, list(h["len"])),
            _robust_z(rate, list(h["rate"])),
            float(sum(h["st"])), float(sum(h["sq"])),
            len(h["dt"]) / HISTORY,
        ])
        if not first:
            h["dt"].append(dt)
        h["val"].append(val)
        h["len"].append(ln)
        h["rate"].append(rate)
        h["st"].append(st_jump)
        h["sq"].append(sq_break)
    x = np.hstack([base, np.asarray(extra, dtype=np.float64).reshape(-1, len(HISTORY_FEATURES))])
    return x, streams


def incidents(times: np.ndarray, alerts: np.ndarray, gap_s: float) -> list[tuple[int, int]]:
    """Group alerting messages into incidents: index ranges of alerts no more
    than gap_s apart (messages in time order)."""
    idx = np.flatnonzero(alerts)
    out: list[tuple[int, int]] = []
    for i in idx:
        if out and times[i] - times[out[-1][1]] <= gap_s:
            out[-1] = (out[-1][0], int(i))
        else:
            out.append((int(i), int(i)))
    return out


def wilson(k, n):
    return gf.wilson(k, n)


def hours(times: np.ndarray) -> float:
    return float(times[-1] - times[0]) / 3600.0 if len(times) > 1 else 0.0


normal_threshold = gf.normal_threshold
read_ipal = gf.read_ipal
is_malicious = gf.is_malicious
with_streams = gf.with_streams
