"""Synthetic adapter contracts, not empirical evidence."""
import json
import subprocess
import unittest
from io import BytesIO

from predict_shield.discovery_adapters import fetch_local_gateway, scan_images, scan_running_image

IMAGE = "sha256:" + "a" * 64


class Response:
    status = 200

    def __init__(self, obj):
        self.stream = BytesIO(json.dumps(obj).encode())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return self.stream.read(size)


class AdapterTests(unittest.TestCase):
    def test_remote_and_credentialed_urls_rejected(self):
        for url in ("https://127.0.0.1:8080/assets",
                    "http://example.com:8080/assets",
                    "http://127.0.0.1/assets",
                    "http://alice:secret@localhost:8080/assets"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch_local_gateway(url)

    def test_live_gateway_validated(self):
        payload = {"schema": "predict-shield/gateway-observation/1",
                   "source": "gateway-routing-export", "collected_at": "2026-11-14T00:00:00Z",
                   "observed_container_ids": ["a" * 64]}
        def opener(req, timeout):
            self.assertEqual(req.get_method(), "GET")
            return Response(payload)
        self.assertEqual(fetch_local_gateway("http://127.0.0.1:8080/assets", opener=opener),
                         payload)

    def test_gateway_duplicate_and_invalid_rejected(self):
        p = {"schema": "predict-shield/gateway-observation/1", "source": "gateway",
             "collected_at": "2026-11-14T00:00:00Z", "observed_container_ids": ["a" * 64] * 2}
        with self.assertRaises(ValueError):
            fetch_local_gateway("http://127.0.0.1:8080/assets", opener=lambda *a, **k: Response(p))

    def test_syft_targets_immutable_image(self):
        commands = []
        def runner(argv, **kwargs):
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                "bomFormat": "CycloneDX", "components": [
                    {"name": "example", "version": "1", "purl": "pkg:maven/example@1"}]}))
        report = scan_running_image(IMAGE, runner=runner)
        self.assertEqual(report["component_count"], 1)
        self.assertEqual(commands[0][1], "docker:" + IMAGE)

    def test_invalid_image_and_scan_failure_remain_unknown(self):
        with self.assertRaises(ValueError):
            scan_running_image("latest")
        def runner(argv, **kwargs):
            raise FileNotFoundError("syft")
        result = scan_images([{"image_id": IMAGE}], runner=runner)
        self.assertEqual(result[IMAGE]["status"], "UNAVAILABLE")
        self.assertNotIn("sbom", result[IMAGE])


if __name__ == "__main__":
    unittest.main()
