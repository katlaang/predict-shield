"""Independent confirmation of successful attacks, registered for the v3.1 Juice Shop test.

Three sources, each matched exactly to a recorded proxy exchange:
  zap        the exact request ZAP stored for an active-scan alert of Medium or High risk
             (fetched from ZAP's message API by the alert's messageId), equal in method,
             request target and body to the recorded exchange
  challenge  a Juice Shop challenge whose solved time falls inside an attack exchange's
             forward/response window (the proxy lets one request through at a time)
  sqlmap     an sqlmap request whose decoded target or body contains a payload sqlmap
             printed as a confirmed injection
"""
from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime


def _target(header: str) -> str:
    line = header.split("\r\n", 1)[0] if "\r\n" in header else header.split("\n", 1)[0]
    parts = line.split(" ")
    if len(parts) < 2:
        return ""
    u = urllib.parse.urlsplit(parts[1])
    return u.path + ("?" + u.query if u.query else "")


def zap_confirmed(recs: list[dict], messages: list[dict], active_ids: set[str]) -> dict[int, str]:
    """messages: [{"pluginId", "risk", "requestHeader", "requestBody", "family"}]."""
    index: dict[tuple, list[int]] = {}
    for i, r in enumerate(recs):
        if r["source"] == "attack":
            index.setdefault((r["method"], r["path"], r.get("body") or ""), []).append(i)
    out = {}
    for m in messages:
        if str(m.get("pluginId")) not in active_ids or m.get("risk") not in ("High", "Medium"):
            continue
        method = (m.get("requestHeader") or "").split(" ", 1)[0]
        key = (method, _target(m.get("requestHeader") or ""), m.get("requestBody") or "")
        for i in index.get(key, []):
            out[i] = m.get("family") or "zap"
    return out


def _ts(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def challenge_confirmed(recs: list[dict], challenges: list[dict], slack: float = 0.05) -> dict[int, str]:
    out = {}
    attack = [(r["t_send"], r["t_recv"], i) for i, r in enumerate(recs) if r["source"] == "attack"]
    for c in challenges:
        if not c.get("solved"):
            continue
        t = _ts(c.get("updatedAt", ""))
        if t is None:
            continue
        for t0, t1, i in attack:
            if t0 - slack <= t <= t1 + slack:
                out[i] = "challenge: " + str(c.get("category", "unknown"))
    return out


PAYLOAD = re.compile(r"^\s*Payload:\s*(.+?)\s*$", re.M)


def sqlmap_payloads(log_text: str) -> list[str]:
    return sorted({p for p in PAYLOAD.findall(log_text) if len(p) >= 6})


def sqlmap_confirmed(recs: list[dict], labels: list[str], payloads: list[str]) -> dict[int, str]:
    out = {}
    for i, (r, l) in enumerate(zip(recs, labels)):
        if l != "sqlmap":
            continue
        text = urllib.parse.unquote_plus(r["path"]) + "\n" + (r.get("body") or "")
        if any(p in text for p in payloads):
            out[i] = "sqli (seen in DVWA)"
    return out
