"""The intake server over real TLS on loopback, with a throwaway PKI."""
import hashlib
import http.client
import json
import ssl
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pki_fixture import TestPKI
from predict_shield.detection_intake import DetectionEvent, RegisteredDetectionSource, sign_detection
from predict_shield.intake_server import DetectionIntakeServer

SIGNER = Ed25519PrivateKey.generate()


def event(source_id, detection_id="d-1"):
    return DetectionEvent(detection_id=detection_id, asset="web-01", source_id=source_id,
                          technique="T1059", confidence=0.8,
                          observed_at=datetime.now(timezone.utc) - timedelta(seconds=5))


class IntakeServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = TestPKI()
        cls.rogue_pki = TestPKI("rogue")
        server_cert, server_key, _ = cls.pki.issue("intake-server", server=True)
        cls.client_cert, cls.client_key, client_der = cls.pki.issue("siem-client", server=False)
        cls.other_client_cert, cls.other_client_key, _ = cls.pki.issue("other-client", server=False)
        cls.rogue_cert, cls.rogue_key, _ = cls.rogue_pki.issue("siem-client", server=False)
        cls.admitted = []
        registry = {
            "ids-signed": RegisteredDetectionSource(
                source_id="ids-signed", name="Lab IDS",
                ed25519_public_key_hex=SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()),
            "siem-mtls": RegisteredDetectionSource(
                source_id="siem-mtls", name="Lab SIEM",
                client_cert_sha256=hashlib.sha256(client_der).hexdigest()),
        }
        cls.server = DetectionIntakeServer(host="127.0.0.1", port=0, certfile=server_cert, keyfile=server_key,
                                           client_ca_file=cls.pki.ca_file, registry=registry,
                                           on_admitted=cls.admitted.append).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def post(self, path, body, client=None):
        context = ssl.create_default_context(cafile=self.pki.ca_file)
        if client:
            context.load_cert_chain(*client)
        conn = http.client.HTTPSConnection("127.0.0.1", self.server.port, context=context, timeout=10)
        data = json.dumps(body).encode()
        conn.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())

    def test_signed_detection_is_admitted_and_its_replay_refused(self):
        envelope = sign_detection(event("ids-signed", "sig-1"), "nonce-1", SIGNER)
        status, body = self.post("/v1/detections", envelope)
        self.assertEqual(status, 202)
        self.assertEqual(body["authentication"], "ed25519")
        status, _ = self.post("/v1/detections", envelope)
        self.assertEqual(status, 401)

    def test_unsigned_claim_of_a_registered_source_is_refused(self):
        envelope = sign_detection(event("ids-signed", "sig-2"), "nonce-2", Ed25519PrivateKey.generate())
        status, body = self.post("/v1/detections", envelope)
        self.assertEqual((status, body), (401, {"error": "detection not admitted"}))

    def test_mtls_with_the_registered_certificate_is_admitted(self):
        payload = sign_detection(event("siem-mtls", "m-1"), "nonce-m1", SIGNER)["payload"]
        status, body = self.post("/v1/detections/mtls", payload, (self.client_cert, self.client_key))
        self.assertEqual(status, 202)
        self.assertEqual(body["authentication"], "mtls")

    def test_mtls_with_another_valid_certificate_from_the_same_ca_is_refused(self):
        payload = sign_detection(event("siem-mtls", "m-2"), "nonce-m2", SIGNER)["payload"]
        status, _ = self.post("/v1/detections/mtls", payload, (self.other_client_cert, self.other_client_key))
        self.assertEqual(status, 401)

    def test_mtls_without_a_client_certificate_is_refused(self):
        payload = sign_detection(event("siem-mtls", "m-3"), "nonce-m3", SIGNER)["payload"]
        status, _ = self.post("/v1/detections/mtls", payload)
        self.assertEqual(status, 401)

    def test_a_certificate_from_an_unregistered_ca_fails_the_handshake(self):
        payload = sign_detection(event("siem-mtls", "m-4"), "nonce-m4", SIGNER)["payload"]
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            self.post("/v1/detections/mtls", payload, (self.rogue_cert, self.rogue_key))


if __name__ == "__main__":
    unittest.main()
