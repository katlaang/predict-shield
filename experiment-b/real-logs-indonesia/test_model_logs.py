import gzip
import io
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_logs as m  # noqa: E402

WORDS = ["jakarta", "bandung", "surat", "berita", "2025", "17", "laporan"]


def line(t: datetime, target: str) -> str:
    return (f'10.0.0.1 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0700] "GET {target} HTTP/1.1" 200 512 '
            f'"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')


class Parsing(unittest.TestCase):
    def test_scope(self):
        self.assertEqual(m.in_scope("organization-x/log/apache2/web-access.log.3.gz"), "x")
        self.assertEqual(m.in_scope("organization-y/log/home/sub1.domain1.com/logs/sub1.domain1.com.access_log.2025_04_19"),
                         "sub1.domain1.com")
        self.assertIsNone(m.in_scope("organization-y/log/usr/local/lsws/logs/access.log"))
        self.assertIsNone(m.in_scope("organization-x/log/apache2/error.log.2.gz"))

    def test_parse_normalizes_digits_and_decodes(self):
        self.assertEqual(m.parse("/news/2025/17/read?id=42&q=kota+baru"), ("/news/9/9/read", "42 kota baru"))
        self.assertIsNone(m.parse("/index.html"))


class EndToEnd(unittest.TestCase):
    def test_develop_test_report(self):
        rng = random.Random(3)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for org, start in (("organization-x", datetime(2025, 9, 23)), ("organization-y", datetime(2025, 4, 10))):
                lines = []
                for i in range(6000):
                    t = start + timedelta(minutes=5 * i)
                    lines.append(line(t, f"/page/{rng.randint(1, 3)}?q={rng.choice(WORDS)}&n={rng.randint(1, 99)}"))
                body = "\n".join(lines).encode()
                with zipfile.ZipFile(root / f"{org}.zip", "w") as z:
                    if org == "organization-x":
                        z.writestr("organization-x/log/apache2/web-access.log.1.gz", gzip.compress(body))
                    else:
                        z.writestr("organization-y/log/home/s1.d.com/logs/s1.d.com.access_log", body)
            for d in ("real-logs-indonesia", "superviz25-sql", "dvwa-correlation-v3", "dvwa-correlation"):
                shutil.copytree(HERE.parent / d, root / d, ignore=shutil.ignore_patterns("frozen", "__pycache__", "reports"))
            proto = json.loads((HERE / "protocol.json").read_text())
            import hashlib
            for org in ("organization-x", "organization-y"):
                proto["source"][f"{org}.zip"]["sha256"] = hashlib.sha256((root / f"{org}.zip").read_bytes()).hexdigest()
            (root / "real-logs-indonesia" / "protocol.json").write_text(json.dumps(proto))
            code = root / "real-logs-indonesia" / "model_logs.py"
            run = lambda *a: subprocess.run([sys.executable, str(code), *a], capture_output=True, text=True)
            zips = [str(root / "organization-x.zip"), str(root / "organization-y.zip")]
            fr, md, wk = root / "frozen", root / "models", root / "work"
            p = run("develop", "--zips", *zips, "--out-dir", str(fr), "--models-dir", str(md))
            self.assertEqual(p.returncode, 0, p.stderr)
            h = json.loads((fr / "freeze.json").read_text())["freeze_sha256"]
            p = run("test", "--zips", *zips, "--frozen-dir", str(fr), "--models-dir", str(md),
                    "--expected-freeze-sha256", h, "--work", str(wk))
            self.assertEqual(p.returncode, 0, p.stderr)
            import numpy as np
            for org in ("organization-x", "organization-y"):
                n = len(json.loads((wk / f"{org}.targets.json").read_text()))
                for k in ("libinj", "crs1", "crs2"):
                    key = "flag" if k == "libinj" else "status"
                    np.savez_compressed(wk / f"{org}.{k}.npz", **{key: np.zeros(n, dtype=bool if k == "libinj" else np.int16)})
            p = run("report", "--work", str(wk), "--frozen-dir", str(fr), "--output", str(fr / "test-report.json"),
                    "--review", str(wk / "review"))
            self.assertEqual(p.returncode, 0, p.stderr)
            rep = json.loads((fr / "test-report.json").read_text())
            self.assertEqual(set(rep["orgs"]), {"organization-x", "organization-y"})
            self.assertLess(rep["orgs"]["organization-x"]["fused"]["alert_rate"], 0.05)


if __name__ == "__main__":
    unittest.main()
