"""Unit and end-to-end tests for version 3 on synthetic files only."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

import features_v3 as fv
import score_test_v3 as st
import train_dev_v3 as td

CIC_HEADER = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"] + \
             [f[1][0] for f in fv.FEATURES] + ["Label", "Attempted Category"]
HIKARI_HEADER = ["Unnamed: 0.1", "Unnamed: 0", "uid", "originh", "originp", "responh", "responp"] + \
                [f[2] for f in fv.FEATURES] + ["traffic_category", "Label"]


def cic_frame(n: int, attack_label: str, rng, offset: int = 0) -> pd.DataFrame:
    rows = []
    for i in range(n):
        attack = i % 4 == 0
        stats = rng.normal(5 if attack else 1, 0.5, len(fv.FEATURES)).clip(0) * (1e5 if attack else 1e3)
        stats[0] = (2e6 if attack else 4e4) * rng.uniform(0.8, 1.2)   # duration in microseconds
        rows.append([offset + i, f"f{i}", "10.0.0.1", 40000, "10.0.0.2", 80 if attack else 443, 6,
                     "2017-07-03 09:00:00"] + list(stats) + [attack_label if attack else "BENIGN", -1])
    return pd.DataFrame(rows, columns=CIC_HEADER)


def write_zip(path: Path, members: dict[str, pd.DataFrame]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for name, frame in members.items():
            z.writestr(name, frame.to_csv(index=False))


def hikari_frame(n: int, rng) -> pd.DataFrame:
    rows = []
    for i in range(n):
        kind = i % 5
        attack = kind == 0
        stats = rng.normal(5 if attack else 1, 0.5, len(fv.FEATURES)).clip(0) * (1e5 if attack else 1e3)
        stats[0] = (2.0 if attack else 0.04) * rng.uniform(0.8, 1.2)   # seconds in Zeek
        cat = "Probing" if attack else ("Background" if kind == 1 else "Benign")
        rows.append([i, i, f"C{i:08d}", "10.1.0.1", 50000, "10.1.0.2", 443] + list(stats)
                    + [cat, 1 if attack else 0])
    return pd.DataFrame(rows, columns=HIKARI_HEADER)


class Mapping(unittest.TestCase):
    def test_resolve_cic_accepts_alternative_spellings(self):
        header = [f[1][-1].upper() for f in fv.FEATURES]
        self.assertEqual(len(fv.resolve_cic(header)), len(fv.FEATURES))

    def test_resolve_cic_reports_missing(self):
        with self.assertRaises(ValueError):
            fv.resolve_cic(["Flow Duration"])

    def test_zeek_duration_seconds_become_microseconds(self):
        frame = hikari_frame(5, np.random.default_rng(0))
        raw = fv.raw_matrix(frame, fv.resolve_hikari(list(frame.columns)), hikari=True)
        self.assertAlmostEqual(raw[0, 0], frame["flow_duration"].iloc[0] * 1e6)
        self.assertAlmostEqual(raw[0, 18], frame["flow_iat.avg"].iloc[0])   # already microseconds

    def test_no_identifier_inputs(self):
        for fs in fv.FEATURE_SETS:
            names = " ".join(fv.feature_names(fs)).lower()
            for banned in ("ip", "timestamp", "label", "uid", "protocol", "cwr", "ece", "subflow", "bulk"):
                self.assertNotIn(f":{banned}", names)

    def test_labels(self):
        self.assertEqual(fv.label_class("FTP-BruteForce"), (True, "brute-force-ftp"))
        self.assertEqual(fv.label_class("Brute Force -Web"), (True, "web-brute-force"))
        self.assertEqual(fv.label_class("Web Attack - Brute Force"), (True, "web-brute-force"))
        self.assertEqual(fv.label_class("Brute Force -XSS"), (True, "web-attack"))
        self.assertEqual(fv.label_class("DoS Hulk - Attempted"), (False, "benign"))
        self.assertEqual(fv.hikari_class("Background", 0), (False, "background"))
        self.assertEqual(fv.hikari_class("XMRIGCC CryptoMiner", 1), (True, "cryptominer"))
        with self.assertRaises(ValueError):
            fv.hikari_class("Benign", 1)

    def test_threshold_budget(self):
        t = fv.normal_threshold(np.arange(1000.0), 0.005)
        self.assertLessEqual(np.mean(np.arange(1000.0) > t), 0.005)


class Sampling(unittest.TestCase):
    def test_bottom_k_keeps_smallest_priorities(self):
        k = td.BottomK(3)
        for start in range(0, 20, 5):
            pri = np.arange(start, start + 5)[::-1] / 100
            k.add(pri, {"v": pri * 100})
        pri, d = k.result()
        self.assertEqual(sorted(d["v"].tolist()), [0, 1, 2])
        self.assertEqual(k.seen, 20)

    def test_priority_and_bucket_independent_and_stable(self):
        p1, b1 = td.priority_and_bucket("n/f", np.arange(2000))
        p2, b2 = td.priority_and_bucket("n/f", np.arange(2000))
        self.assertTrue(np.array_equal(p1, p2) and np.array_equal(b1, b2))
        low = p1 < 0.2
        self.assertGreater(len(set(b1[low].tolist())), 8)


class EndToEnd(unittest.TestCase):
    def test_develop_select_freeze_and_score(self):
        rng = np.random.default_rng(1)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_zip(tmp / "a.zip", {"monday.csv": cic_frame(1500, "PortScan", rng),
                                      "tuesday.csv": cic_frame(1500, "FTP-Patator", rng, 5000)})
            write_zip(tmp / "b.zip", {"Wednesday-14-02-2018.csv": cic_frame(1500, "SSH-Bruteforce", rng)})
            net_a = td.sample_network(tmp / "a.zip", "cic2017", k_benign=400, k_attack=200)
            net_b = td.sample_network(tmp / "b.zip", "cic2018", k_benign=400, k_attack=200)
            self.assertEqual(net_a["rows_by_key"]["monday.csv|benign"], 1125)
            self.assertTrue(np.all(net_a["weight"][net_a["family"] == "benign"] > 1))
            results = []
            for cfg in ({"feature_set": "flow", "max_leaf_nodes": 15, "max_iter": 20},
                        {"feature_set": "flow+service", "max_leaf_nodes": 15, "max_iter": 20}):
                m = td.fit_supervised(td.select_columns(net_a["x"], cfg["feature_set"]), net_a["attack"], 15, 20)
                ev = td.evaluate(net_b, cfg["feature_set"], m)
                self.assertGreater(ev["detection_weighted"], 0.9)
                results.append({"config": cfg, "folds": {"cic2018": {"held_out": ev}},
                                "mean_held_out_detection": ev["detection_weighted"]})
            chosen = td.choose(results)["config"]
            self.assertIn(chosen["feature_set"], fv.FEATURE_SETS)

            # frozen bundle, then the test stage on a synthetic HIKARI file
            hz = tmp / "h.zip"
            write_zip(hz, {"ALLFLOWMETER_HIKARI2021.csv": hikari_frame(3000, rng)})
            code = tmp / "code"
            code.mkdir()
            proto = json.loads((td.HERE / "protocol_v3.json").read_text())
            proto["sources"]["test"]["sha256"] = td.sha256_file(hz)
            for name in td.CODE_FILES:
                src = (td.HERE / name).read_bytes()
                (code / name).write_bytes(json.dumps(proto).encode() if name == "protocol_v3.json" else src)
            x_all = np.vstack([td.select_columns(n["x"], chosen["feature_set"]) for n in (net_a, net_b)])
            y_all = np.concatenate([n["attack"] for n in (net_a, net_b)])
            model = td.fit_supervised(x_all, y_all, 15, 20)
            frozen = tmp / "frozen"
            frozen.mkdir()
            import pickle
            bundle = pickle.dumps({"supervised": model, "config": chosen}, protocol=5)
            (frozen / "supervised.pkl").write_bytes(bundle)
            freeze = {"supervised_sha256": hashlib.sha256(bundle).hexdigest(), "config": chosen,
                      "code_sha256": td.code_hashes(code), "test_pin": td.sha256_file(hz),
                      "development_families": ["portscan", "brute-force-ftp", "brute-force-ssh"]}
            freeze["freeze_sha256"] = hashlib.sha256(json.dumps(freeze, sort_keys=True).encode()).hexdigest()
            (frozen / "freeze.json").write_text(json.dumps(freeze))
            out = tmp / "report.json"
            import sys
            argv = sys.argv
            sys.argv = ["score_test_v3.py", "--archive", str(hz), "--frozen-dir", str(frozen),
                        "--expected-freeze-sha256", freeze["freeze_sha256"], "--output", str(out),
                        "--code-dir", str(code)]
            try:
                st.main()
            finally:
                sys.argv = argv
            r = json.loads(out.read_text())
            self.assertEqual(r["TP"] + r["FP"] + r["FN"] + r["TN"], r["flows"])
            self.assertGreater(r["flows"], 2000)
            self.assertLess(r["flows"], 3000)
            self.assertIn("Background", r["normal_alert_rate_by_category"])
            self.assertTrue(r["by_category"]["Probing"]["family_in_development"])
            self.assertGreater(r["detection_rate"], 0.9)

            # any code change after the freeze is refused
            (code / "score_test_v3.py").write_bytes((td.HERE / "score_test_v3.py").read_bytes() + b"\n")
            with self.assertRaises(SystemExit):
                st.verify(frozen, freeze["freeze_sha256"], hz, code)

    def test_attack_in_normal_set_is_refused(self):
        rng = np.random.default_rng(2)
        with tempfile.TemporaryDirectory() as tmp:
            write_zip(Path(tmp) / "a.zip", {"m.csv": cic_frame(400, "PortScan", rng)})
            net = td.sample_network(Path(tmp) / "a.zip", "n", 400, 400)
            model = td.fit_supervised(net["x"][:, :57], net["attack"], 15, 10)
            net["attack"] = net["attack"].copy()
            net["family"] = net["family"].copy()
            net["family"][:] = "benign"     # family says normal, attack flag says otherwise
            self.assertTrue(net["attack"].any())
            with self.assertRaises(AssertionError):
                td.evaluate(net, "flow", model)


if __name__ == "__main__":
    unittest.main()
