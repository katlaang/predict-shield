"""Offline tests for the public-source adapters. The real fetches run in CI
(public-sources.yml)."""
import base64
import hashlib
import io
import json
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "engine"))

from cdn_scripts import CdnFile, attest, jsdelivr_published_sha256, register  # noqa: E402
from otrf_replay import events_from_archive, fetch_pinned  # noqa: E402

LIB = b"/*! lab library */ window.labLib = {};"
ENTRY = CdnFile("lab", "1.0.0", "lab.min.js", "lab", "/dist/lab.min.js", "labLib")


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def b64(algorithm, data):
    return base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


class FakeCdn:
    def __init__(self, cdnjs_body=LIB, jsdelivr_body=LIB, nested=False):
        self.cdnjs_body, self.jsdelivr_body, self.nested = cdnjs_body, jsdelivr_body, nested

    def __call__(self, request, timeout=None):
        url = request.full_url
        if url.startswith("https://api.cdnjs.com/"):
            return _Response(json.dumps({"sri": {"lab.min.js": "sha512-" + b64("sha512", LIB)}}).encode())
        if url.startswith("https://data.jsdelivr.com/"):
            entry = {"name": "lab.min.js", "hash": b64("sha256", LIB)}
            if self.nested:
                files = [{"type": "directory", "name": "dist", "files": [entry]}]
            else:
                files = [{"name": "/dist/lab.min.js", "hash": b64("sha256", LIB)}]
            return _Response(json.dumps({"files": files}).encode())
        if url.startswith("https://cdnjs.cloudflare.com/"):
            return _Response(self.cdnjs_body)
        if url.startswith("https://cdn.jsdelivr.net/"):
            return _Response(self.jsdelivr_body)
        raise AssertionError("unexpected URL " + url)


class CdnAttestationTests(unittest.TestCase):
    def test_two_publishers_and_identical_bytes_register(self):
        a = attest(ENTRY, FakeCdn())
        self.assertTrue(a.accepted)
        self.assertEqual(register(a).trusted_sha384, (hashlib.sha384(LIB).hexdigest(),))

    def test_nested_jsdelivr_listing_is_understood(self):
        self.assertEqual(jsdelivr_published_sha256(ENTRY, FakeCdn(nested=True)), b64("sha256", LIB))

    def test_a_cdn_serving_different_bytes_is_refused(self):
        a = attest(ENTRY, FakeCdn(cdnjs_body=LIB + b"//tampered"))
        self.assertFalse(a.accepted)
        with self.assertRaises(ValueError):
            register(a)

    def test_cdns_disagreeing_with_each_other_is_refused(self):
        self.assertFalse(attest(ENTRY, FakeCdn(jsdelivr_body=LIB + b" ")).accepted)


class OtrfArchiveTests(unittest.TestCase):
    def test_only_commit_pinned_raw_github_urls_with_the_pinned_hash(self):
        data = b"archive"
        opener = lambda url, timeout=None: _Response(data)  # noqa: E731
        url = "https://raw.githubusercontent.com/OTRF/Security-Datasets/abc/x.zip"
        self.assertEqual(fetch_pinned(url, hashlib.sha256(data).hexdigest(), opener=opener), data)
        with self.assertRaisesRegex(ValueError, "does not match the pinned"):
            fetch_pinned(url, "0" * 64, opener=opener)
        with self.assertRaisesRegex(ValueError, "commit-pinned raw GitHub"):
            fetch_pinned("https://example.com/x.zip", hashlib.sha256(data).hexdigest(), opener=opener)

    def test_zip_and_tar_members_are_read_in_memory(self):
        lines = b'{"EventID": 1}\n{"EventID": 2}\n'
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as z:
            z.writestr("events.json", lines)
            z.writestr("../escape.txt", b"ignored")
        self.assertEqual([e["EventID"] for e in events_from_archive(zbuf.getvalue(), "zip")], [1, 2])
        tbuf = io.BytesIO()
        with tarfile.open(fileobj=tbuf, mode="w:gz") as t:
            info = tarfile.TarInfo("events.json")
            info.size = len(lines)
            t.addfile(info, io.BytesIO(lines))
        self.assertEqual([e["EventID"] for e in events_from_archive(tbuf.getvalue(), "tar.gz")], [1, 2])


if __name__ == "__main__":
    unittest.main()
