import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from predict_shield.telecom_collectors import snmpv3_sysname,gnmi_get_interfaces

class CollectionTests(unittest.TestCase):
    def test_snmp_no_secrets_on_command_line(self):
        def runner(cmd,**kw):
            self.assertIn("-v3",cmd);self.assertIn("authPriv",cmd)
            self.assertNotIn("secret-auth",cmd)
            self.assertNotIn("secret-priv",cmd)
            config=Path(kw["env"]["SNMPCONFPATH"])/"snmp.conf"
            self.assertIn("secret-auth",config.read_text())
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            return subprocess.CompletedProcess(cmd,0,stdout='"edge-a"\n')
        report=snmpv3_sysname(device_id="edge-a",port=1161,user="reader",
             auth_passphrase="secret-auth",privacy_passphrase="secret-priv",runner=runner)
        self.assertEqual(report["assets"][0]["attributes"]["name"],"edge-a")
        self.assertEqual(report["links"],[])
    def test_insecure_snmp_rejected(self):
        with self.assertRaises(ValueError):
            snmpv3_sysname(device_id="edge-a",port=1161,user="reader",
                 auth_passphrase="",privacy_passphrase="secret-priv")
    def test_gnmi_enforces_tls_and_only_get(self):
        with tempfile.TemporaryDirectory() as d:
            paths=[Path(d)/x for x in ("ca","cert","key")]
            for x in paths:x.write_text("test")
            def runner(cmd,**kw):
                self.assertIn("--tls-ca",cmd)
                self.assertNotIn("--insecure",cmd)
                self.assertNotIn("set",cmd)
                self.assertEqual(cmd[-3:],["get","--path","/interfaces/interface/state"])
                return subprocess.CompletedProcess(cmd,0,stdout=json.dumps({"updates":[{}]}))
            r=gnmi_get_interfaces(device_id="edge-a",port=57400,
                    ca=paths[0],client_cert=paths[1],client_key=paths[2],runner=runner)
            self.assertEqual(r["assets"][0]["attributes"]["get_update_count"],1)
    def test_gnmi_rejects_missing_tls(self):
        with self.assertRaises(ValueError):
            gnmi_get_interfaces(device_id="edge-a",port=57400,
              ca=Path("/missing"),client_cert=Path("/missing"),client_key=Path("/missing"))
if __name__=="__main__":unittest.main()
