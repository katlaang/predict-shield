"""Synthetic contract tests: NOT a real running-lab discovery pilot."""
import json
import unittest
from io import BytesIO
from predict_shield.lab_gateway_discovery import live_gateway_routes, reconcile_lab_services

class Response:
    status = 200
    def __init__(self, obj):
        self.data = BytesIO(json.dumps(obj).encode())
    def __enter__(self):
        return self
    def __exit__(self, *unused):
        return False
    def read(self, count):
        return self.data.read(count)

def asset(name, project="mechanism-lab"):
    return {"Id": (name.encode().hex() + "a" * 64)[:64], "Image": "sha256:img",
            "Name": "/" + name, "Config": {"Image": "lab:test",
            "Labels": {"com.docker.compose.project": project,
                       "com.docker.compose.service": name}},
            "State": {"StartedAt": "2026-11-14T20:00:00Z"}}

def routes(*names):
    return {"source": "live-lab-gateway-config", "collected_at": "2026-11-14T20:00:00Z",
            "services": sorted(names)}

class Tests(unittest.TestCase):
    def test_hidden_enforcer_is_detected(self):
        report = reconcile_lab_services([asset("enforcer-a"), asset("enforcer-hidden")],
                                        routes("enforcer-a"), project="mechanism-lab")
        self.assertEqual(report["runtime_only_services"], ["enforcer-hidden"])
        self.assertEqual(report["reconciliation_status"], "DRIFT_DETECTED")
        self.assertEqual(report["security_verification_outcome"], "INDETERMINATE")
    def test_matching_sources_do_not_verify_security(self):
        report = reconcile_lab_services([asset("enforcer-a")], routes("enforcer-a"),
                                        project="mechanism-lab")
        self.assertEqual(report["reconciliation_status"], "RECONCILED_SOURCES")
        self.assertFalse(report["complete_enterprise_scope_verified"])
    def test_other_compose_project_excluded(self):
        report = reconcile_lab_services([asset("enforcer-a"), asset("enforcer-b", "other")],
                                        routes("enforcer-a"), project="mechanism-lab")
        self.assertEqual(report["running_enforcer_services"], ["enforcer-a"])
    def test_gateway_only_drift(self):
        report = reconcile_lab_services([asset("enforcer-a")],
                                        routes("enforcer-a", "enforcer-b"), project="mechanism-lab")
        self.assertEqual(report["gateway_only_services"], ["enforcer-b"])
    def test_bad_routes_rejected(self):
        for candidate in ["http://example.com:8080", "http://enforcer-a:8080/x",
                          "http://enforcer-a:9090"]:
            def opener(req, timeout):
                return Response({"scope": "gateway-config-only", "upstreams": [candidate]})
            with self.assertRaises(ValueError):
                live_gateway_routes("http://127.0.0.1:18280/admin/inventory", "secret", opener=opener)
    def test_requires_authenticated_local_gateway(self):
        with self.assertRaises(ValueError):
            live_gateway_routes("http://example.com:8080/admin/inventory", "secret")
        with self.assertRaises(ValueError):
            live_gateway_routes("http://localhost:18280/admin/inventory", "")
    def test_real_gateway_contract_adapter(self):
        def opener(request, timeout):
            self.assertEqual(request.get_header("X-lab-control"), "secret")
            return Response({"scope": "gateway-config-only",
                             "upstreams": ["http://enforcer-a:8080"], "traffic_profile": "balanced"})
        actual = live_gateway_routes("http://127.0.0.1:18280/admin/inventory", "secret", opener=opener)
        self.assertEqual(actual["services"], ["enforcer-a"])

if __name__ == "__main__":
    unittest.main()
