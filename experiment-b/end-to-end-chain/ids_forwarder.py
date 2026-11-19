"""Forward real Suricata alerts into the detection intake, signed.

Suricata runs as a separate process watching loopback traffic and writes
alerts to eve.json. The forwarder tails that file, maps each alert to a
registered asset, signs it with the IDS source's own Ed25519 key, and
posts it over TLS to `intake_server.DetectionIntakeServer`. The intake
admits it only if the signature verifies against the key registered for
that source.

Mapping is registered, never inferred: an alert maps to the page only
when its destination is a registered sink and its HTTP referrer is the
registered page origin. Any other alert is dropped and counted, never
attached to an asset by guesswork.
"""
from __future__ import annotations

import http.client
import json
import os
import secrets
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from predict_shield.detection_intake import DetectionEvent, sign_detection

LAB_RULES = (
    'alert http any any -> any any (msg:"PREDICT-SHIELD lab: page data sent to a registered sink"; '
    'flow:to_server,established; http.uri; content:"/exfil-"; startswith; '
    'classtype:policy-violation; sid:9900001; rev:1;)\n'
)
SEVERITY_CONFIDENCE = {1: 0.9, 2: 0.7, 3: 0.5}
TECHNIQUE = "T1041"  # exfiltration over an existing channel


@dataclass(frozen=True)
class AlertMapping:
    asset: str
    page_origin: str
    sink_hosts: tuple[str, ...]
    signature_ids: tuple[int, ...] = (9900001,)


def _timestamp(value: str) -> datetime:
    # eve.json uses +HHMM; normalise to +HH:MM for older parsers.
    if len(value) > 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]
    return datetime.fromisoformat(value)


def alert_to_detection(alert: dict, mapping: AlertMapping, source_id: str) -> tuple[DetectionEvent | None, str]:
    if alert.get("event_type") != "alert":
        return None, "not an alert"
    sid = (alert.get("alert") or {}).get("signature_id")
    if sid not in mapping.signature_ids:
        return None, "signature not registered for forwarding"
    http_info = alert.get("http") or {}
    if alert.get("dest_ip") not in mapping.sink_hosts and http_info.get("hostname") not in mapping.sink_hosts:
        return None, "destination is not a registered sink"
    referrer = http_info.get("http_refer") or ""
    parsed = urlparse(referrer)
    if f"{parsed.scheme}://{parsed.netloc}" != mapping.page_origin:
        return None, "referrer is not the registered page"
    severity = (alert.get("alert") or {}).get("severity")
    return DetectionEvent(
        detection_id=f"suricata:{alert.get('flow_id')}:{alert.get('tx_id')}:{sid}",
        asset=mapping.asset, source_id=source_id, technique=TECHNIQUE,
        confidence=SEVERITY_CONFIDENCE.get(severity, 0.5),
        observed_at=_timestamp(alert["timestamp"]),
    ), "mapped"


@dataclass
class ForwarderStats:
    alerts_seen: int = 0
    dropped: dict = field(default_factory=dict)
    posted: list = field(default_factory=list)


class EveForwarder:
    def __init__(self, *, eve_path: Path, mapping: AlertMapping, source_id: str, private_key,
                 intake_host: str, intake_port: int, ca_file: str):
        self.eve_path = Path(eve_path)
        self.mapping = mapping
        self.source_id = source_id
        self.private_key = private_key
        self.intake = (intake_host, intake_port)
        self.context = ssl.create_default_context(cafile=ca_file)
        self.stats = ForwarderStats()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._offset = self.eve_path.stat().st_size if self.eve_path.exists() else 0

    def _post(self, envelope: dict) -> int:
        conn = http.client.HTTPSConnection(*self.intake, context=self.context, timeout=10)
        conn.request("POST", "/v1/detections", body=json.dumps(envelope).encode(),
                     headers={"Content-Type": "application/json"})
        status = conn.getresponse().status
        conn.close()
        return status

    def poll_once(self) -> None:
        if not self.eve_path.exists():
            return
        with self.eve_path.open("r", encoding="utf-8") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
            # keep a partial last line for the next poll
            complete, _, rest = chunk.rpartition("\n")
            self._offset += len(chunk.encode("utf-8")) - len(rest.encode("utf-8"))
        for line in complete.splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("event_type") != "alert":
                continue
            self.stats.alerts_seen += 1
            event, why = alert_to_detection(record, self.mapping, self.source_id)
            if event is None:
                self.stats.dropped[why] = self.stats.dropped.get(why, 0) + 1
                continue
            status = self._post(sign_detection(event, secrets.token_hex(16), self.private_key))
            self.stats.posted.append({"detection_id": event.detection_id, "status": status,
                                      "alert_timestamp": record["timestamp"], "posted_at": time.time()})

    def start(self) -> "EveForwarder":
        def loop():
            while not self._stop.is_set():
                self.poll_once()
                time.sleep(0.2)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


class Suricata:
    """A real Suricata process capturing on loopback with the lab rule only."""

    def __init__(self, workdir: Path, interface: str = "lo", config: str = "/etc/suricata/suricata.yaml",
                 command_prefix: list[str] | None = None):
        self.workdir = Path(workdir)
        self.logdir = self.workdir / "log"
        self.rules = self.workdir / "lab.rules"
        self.interface = interface
        self.config = config
        self.prefix = list(command_prefix or [])
        self.process: subprocess.Popen | None = None

    @property
    def eve(self) -> Path:
        return self.logdir / "eve.json"

    def start(self, timeout: float = 90.0) -> str:
        self.logdir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.logdir, 0o777)
        self.rules.write_text(LAB_RULES)
        cmd = self.prefix + ["suricata", "-c", self.config, f"--pcap={self.interface}", "-k", "none",
                             "-l", str(self.logdir), "-S", str(self.rules),
                             "--set", "unix-command.enabled=no"]
        if os.geteuid() != 0 and self.prefix:
            import grp
            import pwd
            cmd += ["--user", pwd.getpwuid(os.getuid()).pw_name, "--group", grp.getgrgid(os.getgid()).gr_name]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        log = self.logdir / "suricata.log"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if log.exists() and "engine started" in log.read_text(errors="replace").lower():
                version = subprocess.run(["suricata", "-V"], capture_output=True, text=True).stdout.strip()
                return version
            if self.process.poll() is not None:
                raise RuntimeError("suricata exited: " + (log.read_text(errors="replace")[-800:] if log.exists() else ""))
            time.sleep(0.5)
        raise RuntimeError("suricata did not start")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            if self.prefix:
                subprocess.run(self.prefix + ["kill", "-INT", str(self.process.pid)], capture_output=True)
            else:
                self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
