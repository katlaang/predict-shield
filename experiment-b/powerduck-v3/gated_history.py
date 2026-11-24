"""Version 3 GOOSE features: stream history built only from messages judged normal.

Version 2 compared each message with its stream's last HISTORY messages, and
every message entered that history, attack messages included. Once an attack
was sustained, the history was made of attack traffic and the attack looked
normal. Version 3 keeps the same history features but a message enters its
stream's history only when the detector did not alert on it. Scoring is
therefore sequential: each message is scored against the history that the
detector's own earlier decisions admitted.

The forest is scored one message at a time with FastForest, which walks the
fitted scikit-learn trees directly so a capture of a million messages scores
in minutes. FastForest reproduces IsolationForest.score_samples; the unit
tests check that to 1e-9.
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
_NAMES = list(gf.BASE_FEATURES)
I_DT, I_LEN = _NAMES.index("log_dt_stream_ms"), _NAMES.index("length")
I_VAL, I_ST = _NAMES.index("log_mean_abs_value"), _NAMES.index("stnum_delta")
I_SQ, I_RATE = _NAMES.index("sqnum_delta"), _NAMES.index("stream_msgs_last_1s")
I_FIRST = _NAMES.index("first_in_stream")


def _robust_z(value: float, past) -> float:
    if not past:
        return 0.0
    arr = np.fromiter(past, dtype=np.float64)
    med = float(np.median(arr))
    mad = float(np.median(np.abs(arr - med)))
    return max(-20.0, min(20.0, (value - med) / (mad * 1.4826 + 1e-3)))


class StreamHistory:
    """Per-stream history of admitted messages."""

    def __init__(self) -> None:
        self.h: dict[str, dict[str, deque]] = {}

    def _get(self, s: str) -> dict[str, deque]:
        return self.h.setdefault(s, {k: deque(maxlen=HISTORY) for k in ("dt", "val", "len", "rate", "st", "sq")})

    def features(self, row: np.ndarray, s: str) -> list[float]:
        h = self._get(s)
        first = row[I_FIRST] == 1.0
        return [
            _robust_z(row[I_DT], h["dt"]) if not first else 0.0,
            _robust_z(row[I_VAL], h["val"]),
            _robust_z(row[I_LEN], h["len"]),
            _robust_z(row[I_RATE], h["rate"]),
            float(sum(h["st"])), float(sum(h["sq"])),
            len(h["dt"]) / HISTORY,
        ]

    def admit(self, row: np.ndarray, s: str) -> None:
        h = self._get(s)
        first = row[I_FIRST] == 1.0
        if not first:
            h["dt"].append(row[I_DT])
        h["val"].append(row[I_VAL])
        h["len"].append(row[I_LEN])
        h["rate"].append(row[I_RATE])
        h["st"].append(float(row[I_ST] != 0.0) if not first else 0.0)
        h["sq"].append(float(row[I_SQ] != 1.0 and row[I_SQ] != 0.0) if not first else 0.0)


def onehot(s: str, known: list[str]) -> np.ndarray:
    v = np.zeros(len(known) + 1)
    try:
        v[known.index(s)] = 1.0
    except ValueError:
        v[len(known)] = 1.0
    return v


def ungated_features(base: np.ndarray, streams: list[str], known: list[str]) -> np.ndarray:
    """History features with every message admitted (used only to fit the forest on normal captures)."""
    hist = StreamHistory()
    rows = []
    for row, s in zip(base, streams):
        rows.append(np.concatenate([row, hist.features(row, s), onehot(s, known)]))
        hist.admit(row, s)
    return np.asarray(rows)


def _c(n: float) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + 0.5772156649015329) - 2.0 * (n - 1.0) / n


class FastForest:
    """Per-row scoring of a fitted IsolationForest, equal to its score_samples."""

    def __init__(self, model) -> None:
        trees = [e.tree_ for e in model.estimators_]
        n = max(t.node_count for t in trees)
        T = len(trees)
        self.left = np.zeros((T, n), dtype=np.int64)
        self.right = np.zeros((T, n), dtype=np.int64)
        self.feat = np.zeros((T, n), dtype=np.int64)
        self.thr = np.zeros((T, n), dtype=np.float64)
        self.leaf = np.ones((T, n), dtype=bool)
        self.value = np.zeros((T, n), dtype=np.float64)
        depth_max = 0
        for i, (t, feats) in enumerate(zip(trees, model.estimators_features_)):
            k = t.node_count
            lc, rc = t.children_left, t.children_right
            is_leaf = lc == -1
            self.left[i, :k] = np.where(is_leaf, np.arange(k), lc)
            self.right[i, :k] = np.where(is_leaf, np.arange(k), rc)
            self.feat[i, :k] = np.where(is_leaf, 0, np.asarray(feats)[np.maximum(t.feature, 0)])
            self.thr[i, :k] = t.threshold
            self.leaf[i, :k] = is_leaf
            depth = np.zeros(k)
            for node in range(k):
                if not is_leaf[node]:
                    depth[lc[node]] = depth[node] + 1
                    depth[rc[node]] = depth[node] + 1
            depth_max = max(depth_max, int(depth.max()))
            self.value[i, :k] = depth + np.array([_c(m) for m in t.n_node_samples])
        self.steps = depth_max
        self.rows = np.arange(T)
        self.norm = _c(model.max_samples_)

    def score(self, x: np.ndarray) -> float:
        """Same sign as IsolationForest.score_samples (higher is more normal)."""
        x = np.asarray(x, dtype=np.float32).astype(np.float64)
        node = np.zeros(len(self.rows), dtype=np.int64)
        for _ in range(self.steps):
            f = self.feat[self.rows, node]
            go_left = x[f] <= self.thr[self.rows, node]
            node = np.where(go_left, self.left[self.rows, node], self.right[self.rows, node])
        return -(2.0 ** (-self.value[self.rows, node].mean() / self.norm))


def gated_scores(forest: FastForest, threshold: float, base: np.ndarray, streams: list[str],
                 known: list[str]) -> tuple[np.ndarray, np.ndarray]:
    """Score messages in time order. Anomaly score is -score; a message alerts when
    it exceeds threshold, and only non-alerting messages enter their stream's history."""
    hist = StreamHistory()
    scores = np.empty(len(base))
    alerts = np.zeros(len(base), dtype=bool)
    for i, (row, s) in enumerate(zip(base, streams)):
        x = np.concatenate([row, hist.features(row, s), onehot(s, known)])
        a = -forest.score(x)
        scores[i] = a
        if a > threshold:
            alerts[i] = True
        else:
            hist.admit(row, s)
    return scores, alerts


def incidents(times: np.ndarray, alerts: np.ndarray, gap_s: float) -> list[tuple[int, int]]:
    idx = np.flatnonzero(alerts)
    out: list[tuple[int, int]] = []
    for i in idx:
        if out and times[i] - times[out[-1][1]] <= gap_s:
            out[-1] = (out[-1][0], int(i))
        else:
            out.append((int(i), int(i)))
    return out


def hours(times: np.ndarray) -> float:
    return float(times[-1] - times[0]) / 3600.0 if len(times) > 1 else 0.0


capture_features = gf.capture_features
normal_threshold = gf.normal_threshold
read_ipal = gf.read_ipal
is_malicious = gf.is_malicious
wilson = gf.wilson
