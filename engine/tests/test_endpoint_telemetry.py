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


class XmlEventTests(unittest.TestCase):
    LINE = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>10</EventID>"
            "<TimeCreated SystemTime='2022-01-12T16:25:27.967Z'/><EventRecordID>7</EventRecordID>"
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>dc1</Computer></System>"
            "<EventData><Data Name='SourceImage'>C:\\Tools\\dumper.exe</Data>"
            "<Data Name='TargetImage'>C:\\Windows\\system32\\lsass.exe</Data>"
            "<Data Name='GrantedAccess'>0x1fffff</Data></EventData></Event>")

    def test_xml_events_normalize_and_match(self):
        from predict_shield.endpoint_telemetry import RULES_V2, parse_windows_event_xml
        raw = parse_windows_event_xml(self.LINE)
        e = normalize(raw)
        self.assertEqual((e["_channel"], e["_event_id"], e["_host"]), (SYSMON, 10, "dc1"))
        self.assertEqual([h.rule_id for h in detect([raw], RULES_V2)], ["ps2-lsass-memory-access"])

    def test_dtd_and_entities_are_refused(self):
        from predict_shield.endpoint_telemetry import parse_windows_event_xml
        with self.assertRaises(ValueError):
            parse_windows_event_xml('<!DOCTYPE x [<!ENTITY a "aaaa">]><Event/>')


class RulesV2Tests(unittest.TestCase):
    def hit(self, event):
        from predict_shield.endpoint_telemetry import RULES_V2
        return sorted(h.rule_id for h in detect([event], RULES_V2))

    def test_v1_is_preserved_unchanged(self):
        from predict_shield.endpoint_telemetry import RULES, RULES_V1
        self.assertIs(RULES, RULES_V1)
        self.assertEqual([r.rule_id for r in RULES_V1],
                         ["ps-wdigest-downgrade", "ps-lsass-memory-access", "ps-comsvcs-minidump"])

    def test_task_manager_reading_lsass_is_no_longer_skipped(self):
        event = flat(EventID=10, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1fffff",
                     SourceImage="C:\\Windows\\system32\\Taskmgr.exe")
        self.assertEqual(self.hit(event), ["ps2-lsass-memory-access"])

    def test_the_azure_guest_agent_path_is_excluded(self):
        event = flat(EventID=10, TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1410",
                     SourceImage="C:\\WindowsAzure\\GuestAgent_2.7\\CollectGuestLogs.exe")
        self.assertEqual(self.hit(event), [])

    def test_lsass_dump_file_and_command(self):
        self.assertEqual(self.hit(flat(EventID=11, TargetFilename="C:\\Temp\\lsass.DMP")), ["ps2-lsass-dump-file"])
        self.assertEqual(self.hit(flat(EventID=11, TargetFilename="C:\\Temp\\notes.dmp")), [])
        self.assertEqual(self.hit(flat(EventID=1, CommandLine="tool.exe -ma lsass.exe out.dmp")), ["ps2-lsass-dump-command"])

    def test_sam_hive_save(self):
        self.assertEqual(self.hit(flat(EventID=1, CommandLine="reg save HKLM\\SAM C:\\t\\sam")), ["ps2-sam-hive-save"])
        self.assertEqual(self.hit(flat(EventID=1, CommandLine="reg query HKLM\\SAM")), [])

    def test_registered_registry_values(self):
        rdp = "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections"
        self.assertEqual(self.hit(flat(EventID=13, TargetObject=rdp, Details="DWORD (0x00000000)")),
                         ["ps2-security-registry-tamper"])
        self.assertEqual(self.hit(flat(EventID=13, TargetObject=rdp, Details="DWORD (0x00000001)")), [])
        ifeo = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger"
        self.assertEqual(self.hit(flat(EventID=13, TargetObject=ifeo, Details="cmd.exe")), ["ps2-security-registry-tamper"])


if __name__ == "__main__":
    unittest.main()
