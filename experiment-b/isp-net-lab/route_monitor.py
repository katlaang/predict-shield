"""Customer route monitoring: which announced prefixes the customer may not originate.

The registry lists the prefixes a customer is entitled to announce (its
contract or IRR entry). An announcement is authorized only if it is one of
those prefixes or a more-specific inside one of them. Anything else, such as a
more-specific of somebody else's prefix, is a finding.
"""
from __future__ import annotations

import ipaddress


def authorized(prefix: str, registry: list[str]) -> bool:
    net = ipaddress.ip_network(prefix, strict=False)
    return any(net.subnet_of(ipaddress.ip_network(r)) for r in registry)


def unauthorized(received: list[str], registry: list[str]) -> list[str]:
    return sorted(p for p in received if not authorized(p, registry))


def filter_for(registry: list[str]) -> str:
    """Prefix-list content that permits only the registered prefixes (exact length), denying the rest."""
    lines = []
    for i, r in enumerate(sorted(registry, key=lambda x: ipaddress.ip_network(x)), start=1):
        net = ipaddress.ip_network(r)
        lines.append(f"ip prefix-list CUST-IN seq {i * 10} permit {net.with_prefixlen} le {net.prefixlen}")
    return "".join(l + "\n" for l in lines)
