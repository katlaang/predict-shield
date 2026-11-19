"""Turn raw endpoint telemetry (Sysmon and Windows Security events) into
detections, with a small set of registered, inspectable rules.

This is the EDR-shaped input path. A detection produced here is only a
candidate: it reaches the pipeline through the same signed intake as any
other source (`detection_intake.authenticate_signed`), so a rule match
alone never becomes evidence.

Events arrive in two common shapes, both seen in public datasets:
winlogbeat (`event_id`, `log_name`, fields nested under `event_data`) and
NXLog-style flat records (`EventID`, `Channel`, fields at top level).
`normalize()` maps both to one flat shape.

The rules follow widely published detection logic for their techniques.
Each one states exactly which fields it reads and what it matches; there
is no scoring, weighting or learned threshold.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Iterable

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"


def normalize(raw: dict) -> dict:
    fields = dict(raw.get("event_data") or {})
    fields.update({k: v for k, v in raw.items() if k != "event_data"})
    channel = raw.get("Channel") or raw.get("log_name")
    event_id = raw.get("EventID", raw.get("event_id"))
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None
    host = raw.get("Hostname") or raw.get("computer_name")
    if not host:
        beat_host = raw.get("host")
        host = beat_host.get("name") if isinstance(beat_host, dict) else beat_host
    record = raw.get("RecordNumber", raw.get("record_number"))
    when = raw.get("@timestamp") or raw.get("UtcTime") or raw.get("TimeCreated") or raw.get("EventTime")
    fields.update({"_channel": channel, "_event_id": event_id, "_host": host, "_record": record, "_time": when,
                   "_digest": hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16]})
    return fields


def _lower(value) -> str:
    return str(value or "").lower()


def _basename(path) -> str:
    return _lower(path).replace("/", "\\").rsplit("\\", 1)[-1]


@dataclass(frozen=True)
class TelemetryRule:
    rule_id: str
    technique: str
    title: str
    reads: tuple[str, ...]
    matches: Callable[[dict], bool]
    confidence: float
    fields: tuple[str, ...] = ()


# Sysmon event 13: registry value set.
def _wdigest_downgrade(e: dict) -> bool:
    return (e["_channel"] == SYSMON and e["_event_id"] == 13
            and _lower(e.get("TargetObject")).endswith("\\wdigest\\uselogoncredential")
            and _lower(e.get("Details")) in ("1", "dword (0x00000001)"))


# Sysmon event 10: process access. Access masks that allow reading LSASS
# memory, from processes that are not on the registered benign list.
LSASS_READ_MASKS = frozenset({"0x1010", "0x1410", "0x1438", "0x143a", "0x1418", "0x1f0fff", "0x1f1fff", "0x1fffff"})
LSASS_BENIGN_SOURCES = frozenset({"wmiprvse.exe", "svchost.exe", "msmpeng.exe", "csrss.exe", "wininit.exe",
                                  "lsm.exe", "services.exe", "taskmgr.exe", "vmtoolsd.exe"})


def _lsass_memory_access(e: dict) -> bool:
    return (e["_channel"] == SYSMON and e["_event_id"] == 10
            and _basename(e.get("TargetImage")) == "lsass.exe"
            and _lower(e.get("GrantedAccess")) in LSASS_READ_MASKS
            and _basename(e.get("SourceImage")) not in LSASS_BENIGN_SOURCES)


# Process creation (Sysmon 1 or Security 4688): rundll32 calling the
# MiniDump export of comsvcs.dll.
def _comsvcs_minidump(e: dict) -> bool:
    if not ((e["_channel"] == SYSMON and e["_event_id"] == 1) or (e["_channel"] == SECURITY and e["_event_id"] == 4688)):
        return False
    command = _lower(e.get("CommandLine") or e.get("ProcessCommandLine"))
    return "comsvcs" in command and "minidump" in command


RULES_V1: tuple[TelemetryRule, ...] = (
    TelemetryRule("ps-wdigest-downgrade", "T1112", "WDigest set to store plaintext credentials",
                  ("Sysmon 13", "TargetObject", "Details"), _wdigest_downgrade, 0.9,
                  ("TargetObject", "Details", "Image")),
    TelemetryRule("ps-lsass-memory-access", "T1003.001", "LSASS opened with a memory-read access mask",
                  ("Sysmon 10", "TargetImage", "GrantedAccess", "SourceImage"), _lsass_memory_access, 0.8,
                  ("SourceImage", "GrantedAccess", "TargetImage")),
    TelemetryRule("ps-comsvcs-minidump", "T1003.001", "comsvcs.dll MiniDump invoked",
                  ("Sysmon 1 / Security 4688", "CommandLine"), _comsvcs_minidump, 0.9,
                  ("CommandLine",)),
)


# The first rule set, preserved unchanged so its recorded results can be
# reproduced. `RULES` stays bound to it.
RULES = RULES_V1


# ---------------------------------------------------------------- rules v2
#
# Changes from v1 come only from the defects v1 showed on its held-out set
# (OTRF coverage datasets, 2026-11-18) and from generic, widely published
# detection logic. Frozen in a commit before the v2 evaluation data was
# read. Still deterministic field matching, not AI.

LSASS_BENIGN_SOURCES_V2 = LSASS_BENIGN_SOURCES - {"taskmgr.exe"}   # v1 hid a Task Manager LSASS dump
LSASS_BENIGN_PREFIXES_V2 = ("c:\\windowsazure\\",)                 # v1 alerted on the Azure guest agent


def _lsass_memory_access_v2(e: dict) -> bool:
    source = _lower(e.get("SourceImage")).replace("/", "\\")
    return (e["_channel"] == SYSMON and e["_event_id"] == 10
            and _basename(e.get("TargetImage")) == "lsass.exe"
            and _lower(e.get("GrantedAccess")) in LSASS_READ_MASKS
            and _basename(source) not in LSASS_BENIGN_SOURCES_V2
            and not source.startswith(LSASS_BENIGN_PREFIXES_V2))


# Sysmon event 11: file created. A dump file named for LSASS.
def _lsass_dump_file(e: dict) -> bool:
    name = _basename(e.get("TargetFilename"))
    return e["_channel"] == SYSMON and e["_event_id"] == 11 and "lsass" in name and name.endswith(".dmp")


def _process_command(e: dict) -> str | None:
    if (e["_channel"] == SYSMON and e["_event_id"] == 1) or (e["_channel"] == SECURITY and e["_event_id"] == 4688):
        return _lower(e.get("CommandLine") or e.get("ProcessCommandLine"))
    return None


# A process command line naming LSASS together with a dump.
def _lsass_dump_command(e: dict) -> bool:
    command = _process_command(e)
    return bool(command) and "lsass" in command and (".dmp" in command or "minidump" in command or " -ma " in command)


def _comsvcs_minidump_v2(e: dict) -> bool:
    return _comsvcs_minidump(e)


# `reg save` of the SAM, SYSTEM or SECURITY hive.
_HIVE_SAVE = __import__("re").compile(r"\breg(\.exe)?\s+save\s+\"?hklm\\(sam|system|security)\b")


def _sam_hive_save(e: dict) -> bool:
    command = _process_command(e)
    return bool(command) and bool(_HIVE_SAVE.search(command))


# Sysmon event 13: registry value set, on a registered list of
# security-relevant values. Each entry: key suffix, and the values that
# indicate tampering (None: any write).
SECURITY_REGISTRY_VALUES_V2 = (
    ("\\control\\securityproviders\\wdigest\\uselogoncredential", {"1", "dword (0x00000001)"}),
    ("\\control\\terminal server\\fdenytsconnections", {"0", "dword (0x00000000)"}),
    ("\\control\\lsa\\lmcompatibilitylevel", None),
    ("\\control\\lsa\\msv1_0\\ntlmminclientsec", None),
    ("\\control\\lsa\\msv1_0\\restrictsendingntlmtraffic", None),
    ("\\control\\lsa\\disablerestrictedadmin", {"0", "dword (0x00000000)"}),
    ("\\control\\lsa\\runasppl", {"0", "dword (0x00000000)"}),
    ("\\policies\\microsoft\\windows defender\\disableantispyware", {"1", "dword (0x00000001)"}),
    ("\\windows defender\\real-time protection\\disablerealtimemonitoring", {"1", "dword (0x00000001)"}),
    ("\\currentversion\\policies\\system\\enablelua", {"0", "dword (0x00000000)"}),
)


def _security_registry_tamper(e: dict) -> bool:
    if not (e["_channel"] == SYSMON and e["_event_id"] == 13):
        return False
    target = _lower(e.get("TargetObject"))
    details = _lower(e.get("Details"))
    if "\\image file execution options\\" in target and target.endswith("\\debugger"):
        return True
    return any(target.endswith(suffix) and (values is None or details in values)
               for suffix, values in SECURITY_REGISTRY_VALUES_V2)


RULES_V2: tuple[TelemetryRule, ...] = (
    TelemetryRule("ps2-lsass-memory-access", "T1003.001", "LSASS opened with a memory-read access mask",
                  ("Sysmon 10", "TargetImage", "GrantedAccess", "SourceImage"), _lsass_memory_access_v2, 0.8,
                  ("SourceImage", "GrantedAccess", "TargetImage")),
    TelemetryRule("ps2-lsass-dump-file", "T1003.001", "A dump file named for LSASS was written",
                  ("Sysmon 11", "TargetFilename"), _lsass_dump_file, 0.9, ("TargetFilename", "Image")),
    TelemetryRule("ps2-lsass-dump-command", "T1003.001", "A command line names LSASS and a dump",
                  ("Sysmon 1 / Security 4688", "CommandLine"), _lsass_dump_command, 0.9, ("CommandLine",)),
    TelemetryRule("ps2-comsvcs-minidump", "T1003.001", "comsvcs.dll MiniDump invoked",
                  ("Sysmon 1 / Security 4688", "CommandLine"), _comsvcs_minidump_v2, 0.9, ("CommandLine",)),
    TelemetryRule("ps2-sam-hive-save", "T1003.002", "SAM, SYSTEM or SECURITY hive saved with reg save",
                  ("Sysmon 1 / Security 4688", "CommandLine"), _sam_hive_save, 0.9, ("CommandLine",)),
    TelemetryRule("ps2-security-registry-tamper", "T1112", "A registered security-relevant registry value changed",
                  ("Sysmon 13", "TargetObject", "Details"), _security_registry_tamper, 0.8,
                  ("TargetObject", "Details", "Image")),
)


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    technique: str
    host: str | None
    record: object
    event_digest: str
    event_time: str | None
    matched: tuple = ()


def detect(events: Iterable[dict], rules: tuple[TelemetryRule, ...] = RULES) -> list[RuleHit]:
    hits = []
    for raw in events:
        e = normalize(raw)
        for rule in rules:
            if rule.matches(e):
                matched = tuple((f, str(e.get(f) or e.get("ProcessCommandLine") if f == "CommandLine" else e.get(f))[:300])
                                for f in rule.fields)
                hits.append(RuleHit(rule.rule_id, rule.technique, e["_host"], e["_record"], e["_digest"], e["_time"],
                                    matched))
    return hits


def technique_matches_label(technique: str, labels: Iterable[str]) -> bool:
    """A hit agrees with a published label when it names the same technique,
    or a sub-technique of a labelled parent."""
    return any(technique == label or technique.startswith(label + ".") for label in labels)
