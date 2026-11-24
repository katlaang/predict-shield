"""Version 3 features: one feature space shared by two flow meters.

Development data is CICFlowMeter output (CIC-IDS2017 and CSE-CIC-IDS2018,
improved versions). The test data, HIKARI-2021, was produced by the Zeek
flowmeter package. Both describe a flow with similar statistics under
different names and, for some fields, different units. Each feature below is
defined once, with the CICFlowMeter column name(s) that carry it and the Zeek
flowmeter column, plus the factor that converts the Zeek value into
CICFlowMeter units.

Units come from the tools' documentation and source, never from looking at
the test data:
  * Zeek flowmeter logs flow_duration as a Zeek interval (seconds) and
    multiplies every inter-arrival, active and idle time by 1,000,000
    (microseconds); scripts/flowmeter.zeek.
  * CICFlowMeter reports durations, inter-arrival, active and idle times in
    microseconds, rates per second and lengths in bytes.
  * Both use a 5 s active timeout.

Left out on purpose:
  * protocol: HIKARI-2021 has no protocol column;
  * timestamp context: HIKARI-2021 has no timestamp column;
  * subflow and bulk fields: the two tools define them differently;
  * CWR and ECE counts: the flowmeter script logs them swapped;
  * addresses, ports (except the destination-service bucket), flow ids,
    timestamps and labels.
"""
from __future__ import annotations

import hashlib
import math
import re

import numpy as np
import pandas as pd

# (feature, CICFlowMeter names (any one may appear), Zeek flowmeter name, factor to CIC units)
FEATURES = (
    ("duration_us", ("Flow Duration",), "flow_duration", 1e6),
    ("fwd_packets", ("Total Fwd Packet", "Total Fwd Packets"), "fwd_pkts_tot", 1.0),
    ("bwd_packets", ("Total Bwd packets", "Total Bwd Packets", "Total Backward Packets"), "bwd_pkts_tot", 1.0),
    ("fwd_data_packets", ("Fwd Act Data Pkts", "act_data_pkt_fwd"), "fwd_data_pkts_tot", 1.0),
    ("fwd_payload_total", ("Total Length of Fwd Packet", "Total Length of Fwd Packets",
                           "Fwd Packets Length Total"), "fwd_pkts_payload.tot", 1.0),
    ("bwd_payload_total", ("Total Length of Bwd Packet", "Total Length of Bwd Packets",
                           "Bwd Packets Length Total"), "bwd_pkts_payload.tot", 1.0),
    ("fwd_payload_max", ("Fwd Packet Length Max",), "fwd_pkts_payload.max", 1.0),
    ("fwd_payload_min", ("Fwd Packet Length Min",), "fwd_pkts_payload.min", 1.0),
    ("fwd_payload_mean", ("Fwd Packet Length Mean",), "fwd_pkts_payload.avg", 1.0),
    ("fwd_payload_std", ("Fwd Packet Length Std",), "fwd_pkts_payload.std", 1.0),
    ("bwd_payload_max", ("Bwd Packet Length Max",), "bwd_pkts_payload.max", 1.0),
    ("bwd_payload_min", ("Bwd Packet Length Min",), "bwd_pkts_payload.min", 1.0),
    ("bwd_payload_mean", ("Bwd Packet Length Mean",), "bwd_pkts_payload.avg", 1.0),
    ("bwd_payload_std", ("Bwd Packet Length Std",), "bwd_pkts_payload.std", 1.0),
    ("payload_min", ("Packet Length Min", "Min Packet Length"), "flow_pkts_payload.min", 1.0),
    ("payload_max", ("Packet Length Max", "Max Packet Length"), "flow_pkts_payload.max", 1.0),
    ("payload_mean", ("Packet Length Mean",), "flow_pkts_payload.avg", 1.0),
    ("payload_std", ("Packet Length Std",), "flow_pkts_payload.std", 1.0),
    ("flow_iat_mean_us", ("Flow IAT Mean",), "flow_iat.avg", 1.0),
    ("flow_iat_std_us", ("Flow IAT Std",), "flow_iat.std", 1.0),
    ("flow_iat_max_us", ("Flow IAT Max",), "flow_iat.max", 1.0),
    ("flow_iat_min_us", ("Flow IAT Min",), "flow_iat.min", 1.0),
    ("fwd_iat_total_us", ("Fwd IAT Total",), "fwd_iat.tot", 1.0),
    ("fwd_iat_mean_us", ("Fwd IAT Mean",), "fwd_iat.avg", 1.0),
    ("fwd_iat_std_us", ("Fwd IAT Std",), "fwd_iat.std", 1.0),
    ("fwd_iat_max_us", ("Fwd IAT Max",), "fwd_iat.max", 1.0),
    ("fwd_iat_min_us", ("Fwd IAT Min",), "fwd_iat.min", 1.0),
    ("bwd_iat_total_us", ("Bwd IAT Total",), "bwd_iat.tot", 1.0),
    ("bwd_iat_mean_us", ("Bwd IAT Mean",), "bwd_iat.avg", 1.0),
    ("bwd_iat_std_us", ("Bwd IAT Std",), "bwd_iat.std", 1.0),
    ("bwd_iat_max_us", ("Bwd IAT Max",), "bwd_iat.max", 1.0),
    ("bwd_iat_min_us", ("Bwd IAT Min",), "bwd_iat.min", 1.0),
    ("fwd_psh_flags", ("Fwd PSH Flags",), "fwd_PSH_flag_count", 1.0),
    ("bwd_psh_flags", ("Bwd PSH Flags",), "bwd_PSH_flag_count", 1.0),
    ("fwd_urg_flags", ("Fwd URG Flags",), "fwd_URG_flag_count", 1.0),
    ("bwd_urg_flags", ("Bwd URG Flags",), "bwd_URG_flag_count", 1.0),
    ("fin_flags", ("FIN Flag Count",), "flow_FIN_flag_count", 1.0),
    ("syn_flags", ("SYN Flag Count",), "flow_SYN_flag_count", 1.0),
    ("rst_flags", ("RST Flag Count",), "flow_RST_flag_count", 1.0),
    ("ack_flags", ("ACK Flag Count",), "flow_ACK_flag_count", 1.0),
    ("fwd_header_bytes", ("Fwd Header Length",), "fwd_header_size_tot", 1.0),
    ("bwd_header_bytes", ("Bwd Header Length",), "bwd_header_size_tot", 1.0),
    ("fwd_packets_per_s", ("Fwd Packets/s",), "fwd_pkts_per_sec", 1.0),
    ("bwd_packets_per_s", ("Bwd Packets/s",), "bwd_pkts_per_sec", 1.0),
    ("flow_packets_per_s", ("Flow Packets/s",), "flow_pkts_per_sec", 1.0),
    ("flow_payload_bytes_per_s", ("Flow Bytes/s",), "payload_bytes_per_second", 1.0),
    ("down_up_ratio", ("Down/Up Ratio",), "down_up_ratio", 1.0),
    ("fwd_init_window", ("FWD Init Win Bytes", "Init_Win_bytes_forward", "Init Fwd Win Bytes"),
     "fwd_init_window_size", 1.0),
    ("bwd_init_window", ("Bwd Init Win Bytes", "Init_Win_bytes_backward", "Init Bwd Win Bytes"),
     "bwd_init_window_size", 1.0),
    ("active_mean_us", ("Active Mean",), "active.avg", 1.0),
    ("active_std_us", ("Active Std",), "active.std", 1.0),
    ("active_max_us", ("Active Max",), "active.max", 1.0),
    ("active_min_us", ("Active Min",), "active.min", 1.0),
    ("idle_mean_us", ("Idle Mean",), "idle.avg", 1.0),
    ("idle_std_us", ("Idle Std",), "idle.std", 1.0),
    ("idle_max_us", ("Idle Max",), "idle.max", 1.0),
    ("idle_min_us", ("Idle Min",), "idle.min", 1.0),
)
FEATURE_NAMES = tuple(f[0] for f in FEATURES)

SERVICE_PORTS = (20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
                 445, 465, 587, 993, 995, 1433, 3306, 3389, 5353, 5355, 8080, 8443)
SERVICE_NAMES = tuple(f"port-{p}" for p in SERVICE_PORTS) + ("ephemeral", "registered", "other-wellknown",
                                                             "unknown")
FEATURE_SETS = ("flow", "flow+service")

CIC_PORT = "Dst Port"
CIC_ID = "id"
CIC_LABEL = "Label"
HIKARI_PORT = "responp"
HIKARI_ID = "uid"
HIKARI_CATEGORY = "traffic_category"
HIKARI_LABEL = "Label"

FAMILY_PATTERNS = (
    ("heartbleed", r"heartbleed"),
    ("brute-force-ftp", r"ftp"),
    ("brute-force-ssh", r"ssh"),
    ("web-brute-force", r"web.*brute|brute.*web"),
    ("web-attack", r"web.?attack|xss|sql"),
    ("infiltration", r"infil"),
    ("ddos", r"ddos|loic|hoic"),
    ("dos-slow", r"slowloris|slowhttp"),
    ("dos-hulk", r"hulk"),
    ("dos-goldeneye", r"goldeneye"),
    ("botnet", r"bot|ares|zeus"),
    ("portscan", r"port.?scan|nmap"),
)
# HIKARI-2021 categories mapped to the family names above where the attack is
# the same kind; a category with no counterpart keeps its own name.
HIKARI_FAMILIES = {
    "Probing": "portscan",
    "Bruteforce": "web-brute-force",
    "Bruteforce-XML": "web-brute-force",
    "XMRIGCC CryptoMiner": "cryptominer",
}
HIKARI_NORMAL = ("Benign", "Background")


def normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def resolve_cic(header: list[str]) -> dict[str, str]:
    """Feature name -> CIC column actually present. Raises if any is missing."""
    present = {normalise(h): h for h in header}
    out, missing = {}, []
    for feature, cic_names, _, _ in FEATURES:
        hit = next((present[normalise(n)] for n in cic_names if normalise(n) in present), None)
        if hit is None:
            missing.append(feature)
        else:
            out[feature] = hit
    if missing:
        raise ValueError(f"CIC header lacks {missing}; header was {header}")
    return out


def resolve_hikari(header: list[str]) -> dict[str, str]:
    present = set(header)
    missing = [z for _, _, z, _ in FEATURES if z not in present]
    if missing:
        raise ValueError(f"HIKARI header lacks {missing}")
    return {f: z for f, _, z, _ in FEATURES}


def label_class(label: str) -> tuple[bool, str]:
    """CIC labels: BENIGN and every 'Attempted' label are benign."""
    text = (label or "").strip()
    if not text or text.upper() == "BENIGN" or re.search(r"attempted", text, re.I):
        return False, "benign"
    for family, pattern in FAMILY_PATTERNS:
        if re.search(pattern, text, re.I):
            return True, family
    return True, "unmapped"


def hikari_class(category: str, label) -> tuple[bool, str]:
    """HIKARI-2021: Label 1 is an attack. Benign and Background are normal.
    A category that disagrees with Label raises, since it would mean the
    file is not what was pinned."""
    attack = int(label) == 1
    if category in HIKARI_NORMAL:
        if attack:
            raise ValueError(f"category {category!r} with Label 1")
        return False, category.lower()
    if not attack:
        raise ValueError(f"category {category!r} with Label 0")
    return True, HIKARI_FAMILIES.get(category, "unmapped")


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


def raw_matrix(frame: pd.DataFrame, columns: dict[str, str], hikari: bool) -> np.ndarray:
    """Flow statistics in CICFlowMeter units, before the log transform."""
    cols = []
    for feature, _, _, factor in FEATURES:
        v = pd.to_numeric(frame[columns[feature]], errors="coerce").to_numpy(dtype=np.float64)
        cols.append(v * factor if hikari else v)
    return np.column_stack(cols)


def build(frame: pd.DataFrame, columns: dict[str, str], port_column: str, *, hikari: bool,
          feature_set: str) -> np.ndarray:
    if feature_set not in FEATURE_SETS:
        raise ValueError(feature_set)
    parts = [signed_log(raw_matrix(frame, columns, hikari))]
    if feature_set == "flow+service":
        svc = frame[port_column].map(service_bucket).to_numpy()
        parts.append(np.column_stack([(svc == s) for s in SERVICE_NAMES]).astype(np.float64))
    return np.hstack(parts).astype(np.float32)


def feature_names(feature_set: str) -> list[str]:
    names = [f"log:{f}" for f in FEATURE_NAMES]
    return names + ([f"svc:{s}" for s in SERVICE_NAMES] if feature_set == "flow+service" else [])


def row_hash(source: str, row_id) -> float:
    """Uniform in [0, 1) from SHA-256; fixes sampling and splits."""
    digest = hashlib.sha256(f"{source}\x00{row_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2.0 ** 64


def split_bucket(source: str, row_id) -> int:
    return int(row_hash(source, row_id) * 10)


def normal_threshold(scores: np.ndarray, max_rate: float) -> float:
    """Smallest observed cutoff t with the share of scores strictly above t at
    most max_rate. Alert when score > t."""
    s = np.sort(np.asarray(scores, dtype=np.float64))
    n = len(s)
    if n == 0:
        raise ValueError("no calibration scores")
    allowed = int(math.floor(max_rate * n))
    return float(s[n - 1 - allowed]) if allowed < n else float(s[0])


def wilson(k: int, n: int, z: float = 1.959964):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]
