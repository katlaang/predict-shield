import unittest

from predict_shield.endpoint_telemetry import detect, normalize, technique_matches_label

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def flat(**fields):
    base = {"Channel": SYSMON, "Hostname": "HOST1", "RecordNumber": 1}
    base.update(fields)
    return base


def beat(event_id, **event_data):
    return {"log_name": SYSMON, "event_id": event_id, "computer_name": "HOST2", "record_number": 7,
            "event_data": event_data}


class NormalizeTests(unittest.TestCase):
    def test_both_public_dataset_shapes_normalize_to_one(self):
        a = normalize(flat(EventID=10, TargetImage="C:\\Windows\\system32\\lsass.exe"))
        b = normalize(beat(10, TargetImage="C:\\Windows\\system32\\lsass.exe"))
        for e, host in ((a, "HOST1"), (b, "HOST2")):
            self.assertEqual((e["_channel"], e["_event_id"], e["_host"]), (SYSMON, 10, host))
            self.assertTrue(e["TargetImage"].endswith("lsass.exe"))


class RuleTests(unittest.TestCase):
    def rules_hit(self, event):
        return sorted(h.rule_id for h in detect([event]))

    def test_wdigest_downgrade_fires_only_when_enabled(self):
        key = "HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
        self.assertEqual(self.rules_hit(beat(13, TargetObject=key, Details="1")), ["ps-wdigest-downgrade"])
        self.assertEqual(self.rules_hit(beat(13, TargetObject=key, Details="DWORD (0x00000000)")), [])

    def test_lsass_read_from_an_unlisted_process_fires(self):
        event = flat(EventID=10, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1010",
                     SourceImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertEqual(self.rules_hit(event), ["ps-lsass-memory-access"])

    def test_benign_lsass_access_does_not_fire(self):
        for source, mask in (("C:\\Windows\\system32\\svchost.exe", "0x1010"),
                             ("C:\\Windows\\System32\\powershell.exe", "0x1000")):
            event = flat(EventID=10, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess=mask,
                         SourceImage=source)
            self.assertEqual(self.rules_hit(event), [], (source, mask))

    def test_comsvcs_minidump_fires_from_either_process_creation_source(self):
        cmd = "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 756 out.dmp full"
        self.assertEqual(self.rules_hit(flat(EventID=1, CommandLine=cmd)), ["ps-comsvcs-minidump"])
        self.assertEqual(self.rules_hit({"Channel": "Security", "EventID": 4688, "CommandLine": cmd}),
                         ["ps-comsvcs-minidump"])
        self.assertEqual(self.rules_hit(flat(EventID=1, CommandLine="rundll32.exe comsvcs.dll,Other")), [])

    def test_sub_technique_agrees_with_its_parent_label_only(self):
        self.assertTrue(technique_matches_label("T1003.001", ["T1003"]))
        self.assertTrue(technique_matches_label("T1003.001", ["T1003.001"]))
        self.assertFalse(technique_matches_label("T1003.001", ["T1003.002"]))
        self.assertFalse(technique_matches_label("T1112", ["T1003"]))


if __name__ == "__main__":
    unittest.main()
