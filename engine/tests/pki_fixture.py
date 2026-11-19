"""Throwaway test PKI: a CA, a server certificate for 127.0.0.1, and client
certificates. Generated fresh per test run; nothing is reused or committed."""
from __future__ import annotations

import datetime
import ipaddress
import os
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write(directory: str, filename: str, data: bytes) -> str:
    path = os.path.join(directory, filename)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class TestPKI:
    def __init__(self, label: str = "predict-shield-test"):
        self.dir = tempfile.mkdtemp(prefix="ps-pki-")
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        self._now = now
        self.ca_cert = (x509.CertificateBuilder()
                        .subject_name(_name(label + " CA")).issuer_name(_name(label + " CA"))
                        .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now - datetime.timedelta(minutes=5))
                        .not_valid_after(now + datetime.timedelta(days=1))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                     key_encipherment=False, data_encipherment=False,
                                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                     encipher_only=False, decipher_only=False), critical=True)
                        .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                                       critical=False)
                        .sign(self.ca_key, hashes.SHA256()))
        self.ca_file = _write(self.dir, "ca.pem", self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, common_name: str, *, server: bool) -> tuple[str, str, bytes]:
        """Return (certfile, keyfile, certificate DER)."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder()
                   .subject_name(_name(common_name)).issuer_name(self.ca_cert.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(self._now - datetime.timedelta(minutes=5))
                   .not_valid_after(self._now + datetime.timedelta(days=1))
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                                  critical=False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if server:
            builder = (builder.add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        else:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        cert = builder.sign(self.ca_key, hashes.SHA256())
        certfile = _write(self.dir, common_name + ".pem", cert.public_bytes(serialization.Encoding.PEM))
        keyfile = _write(self.dir, common_name + ".key", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return certfile, keyfile, cert.public_bytes(serialization.Encoding.DER)
