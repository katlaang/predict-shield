"""Synthetic unit tests; never interpreted as live discovery evidence."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from predict_shield.asset_discovery import (
    build_report, docker_inspect, load_gateway_snapshot, normalize_runtime,
)


def fixture(container_id="a" * 64):
    return {
        "Id": container_id, "Name": "/enforcer-a", "Image": "sha256:abc",
        "State": {"StartedAt": "2026-11-14T12:00:00Z"},
        "Config": {"Image": "test-enforcer@sha256:123",
                   "Labels": {"com.docker.compose.service": "enforcer",
                              "com.docker.compose.project": "mechanism-lab"}},
    }


def gateway(ids):
    return {"schema": "predict-shield/gateway-observation/1",
            "source": "test-independent-file",
            "collected_at": "2026-11-14T13:00:00Z",
            "observed_container_ids": ids}


class DiscoveryTests(unittest.TestCase):
    def test_runtime_normalization_and_unowned_report(self):
        report = build_report([fixture()])
        self.assertEqual(report["assets"][0]["service"], "enforcer")
        self.assertEqual(report["reconciliation"]["scope_status"], "INDETERMINATE")
        self.assertEqual(len(report["reconciliation"]["missing_owner"]), 1)
        self.assertFalse(report["complete_enterprise_inventory_verified"])

    def test_reconciled_membership_does_not_claim_verified(self):
        result = build_report([fixture()], gateway(["a" * 64]))
        self.assertEqual(result["reconciliation"]["scope_status"], "RECONCILED_SOURCES")
        self.assertFalse(result["source_independence_authenticated"])
        self.assertFalse(result["complete_enterprise_inventory_verified"])

    def test_drift_both_directions(self):
        report = build_report([fixture()], gateway(["b" * 64]))
        self.assertEqual(report["reconciliation"]["runtime_only"], ["a" * 64])
        self.assertEqual(report["reconciliation"]["gateway_only"], ["b" * 64])
        self.assertEqual(report["reconciliation"]["scope_status"], "DRIFT_DETECTED")

    def test_duplicate_runtime_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            normalize_runtime([fixture(), fixture()])

    def test_gateway_schema_and_duplicates_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "gateway.json"
            p.write_text(json.dumps(gateway(["a" * 64, "a" * 64])))
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                load_gateway_snapshot(p)
            p.write_text(json.dumps({"observed_container_ids": []}))
            with self.assertRaisesRegex(ValueError, "schema"):
                load_gateway_snapshot(p)

    def test_docker_read_only_commands_and_failure(self):
        commands = []
        def runner(command, **kwargs):
            commands.append(command)
            if command[1] == "ps":
                return subprocess.CompletedProcess(command, 0, stdout="a" * 64 + "\n")
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([fixture()]))
        self.assertEqual(len(docker_inspect(runner=runner)), 1)
        self.assertEqual(commands[0][:2], ["docker", "ps"])
        self.assertEqual(commands[1][:3], ["docker", "container", "inspect"])

    def test_incomplete_inspect_is_rejected(self):
        def runner(command, **kwargs):
            if command[1] == "ps":
                return subprocess.CompletedProcess(command, 0, stdout="a" * 64 + "\n")
            return subprocess.CompletedProcess(command, 0, stdout="[]")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            docker_inspect(runner=runner)


if __name__ == "__main__":
    unittest.main()
