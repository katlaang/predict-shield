"""Version comparison and affected ranges.

Deliberately narrow: dotted numeric versions with an optional release suffix
(`.Final`, `.RELEASE`, `.GA`). Anything else raises `UnsupportedVersion`, and
callers abstain. A wrong ordering would silently mark a vulnerable instance as
fixed, so refusing is the safe behaviour.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION = re.compile(r"^(\d+(?:\.\d+)*)(?:[.-](?:final|release|ga))?$", re.IGNORECASE)


class UnsupportedVersion(ValueError):
    pass


def parse(version: str) -> tuple[int, ...]:
    match = _VERSION.match(version.strip()) if isinstance(version, str) else None
    if match is None:
        raise UnsupportedVersion(f"cannot order version {version!r}")
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:        # 2.0 and 2.0.0 are the same release
        parts.pop()
    return tuple(parts)


@dataclass(frozen=True)
class VersionRange:
    """Half-open range: affected from `introduced` (inclusive) up to `fixed` (exclusive).

    `introduced=None` means every version before `fixed`. `fixed=None` means no
    fixed release is known, so every version from `introduced` on is affected.
    """
    introduced: str | None
    fixed: str | None

    def __post_init__(self) -> None:
        if self.introduced is None and self.fixed is None:
            raise ValueError("a range needs at least one bound")
        low = parse(self.introduced) if self.introduced is not None else None
        high = parse(self.fixed) if self.fixed is not None else None
        if low is not None and high is not None and not low < high:
            raise ValueError("introduced must be lower than fixed")

    def contains(self, version: str) -> bool:
        value = parse(version)
        if self.introduced is not None and value < parse(self.introduced):
            return False
        return self.fixed is None or value < parse(self.fixed)
