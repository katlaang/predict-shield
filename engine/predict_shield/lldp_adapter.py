"""Read-only, permission-scoped LLDP neighbor snapshot importer.

Works on an externally exported standard normalized LLDP JSON snapshot.
No credentials, scanning, SNMP writes, or assumptions about ownership.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress


def lldp_to_source_export(payload: dict, *, source_id: str, collected_at: str) -> dict:
    """Normalize collector observations from a monitored interface inventory."""
    if payload.get("schema") != "predict-shield/lldp-export/1":
        raise ValueError("Unsupported LLDP observation contract")
    devices=payload.get("devices")
    if not isinstance(devices,list):
        raise ValueError("LLDP devices must be a list")
    assets={}
    links=[]
    for device in devices:
        if not isinstance(device,dict):
            raise ValueError("Invalid LLDP device")
        local=device.get("device_id")
        if not isinstance(local,str) or not local:
            raise ValueError("Missing LLDP local chassis identity")
        host_ip=device.get("management_ip")
        if host_ip:
            ipaddress.ip_address(host_ip)
        assets[local]={"asset_id":local,"type":device.get("device_type","switch"),
                       "attributes":{"management_ip":host_ip,"name":device.get("name")}}
        for neighbor in device.get("neighbors",[]):
            remote=neighbor.get("neighbor_id")
            local_port=neighbor.get("local_port")
            remote_port=neighbor.get("remote_port")
            if not all(isinstance(x,str) and x for x in (remote,local_port,remote_port)):
                raise ValueError("Missing LLDP neighboring chassis or port")
            if remote==local:
                raise ValueError("Self LLDP neighbor")
            evidence_id="lldp:"+local+"/"+local_port+"->"+remote+"/"+remote_port
            # Remote endpoint is NOT silently fabricated as a fully observed asset.
            links.append({"source":local,"target":remote,"relation":"NEIGHBOR_OF",
                          "evidence_id":evidence_id})
    return {"schema":"predict-shield/telecom-source-export/1",
            "source_kind":"lldp","source_id":source_id,
            "collected_at":collected_at,
            "assets":sorted(assets.values(),key=lambda a:a["asset_id"]),
            "links":links}
