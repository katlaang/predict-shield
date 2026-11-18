"""Screen untrusted advisory/log/document text for attempts to steer the agent.

PREDICT-SHIELD already refuses to let a language model's reply introduce a
package or version the inputs do not support (`advisory_reader.validate_reply`,
`action_proposer.validate_reply`). That grounding check is the main defense,
and it holds regardless of what this module finds.

This module adds a second, independent, pre-model layer: look at the raw text
*before* it reaches the model and flag language that reads as an attempt to
instruct the agent rather than describe a vulnerability. It is pattern-based,
not a model, and intentionally conservative. It is here to produce a signal
an operator can review and to add match examples to over time, not to make an
unreviewed accept/reject decision on its own, and not to replace the grounding
check above.

What it is not: a jailbreak classifier trained on attack data (that is a
larger, separate effort). This is the fast, auditable first layer the
rapid-response literature calls for: recognizing a *class* of attack from a
handful of concrete patterns, so a batch of advisories can be triaged before
any of them reach a model prompt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Patterns describing an attempt to redirect what the agent does, rather than
# describe a vulnerability. Each is a regex over lowercased text. Add new
# entries as concrete examples are found; keep them specific enough that
# ordinary advisory prose ("ignore version 1.2, it was a packaging mistake")
# does not match.
_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"ignore (?:the )?(?:above|previous|prior|all)(?:\s+\w+)? instructions", "instruction override"),
    (r"disregard (?:the )?(?:system|previous|prior) prompt", "instruction override"),
    (r"you are now|act as (?:a|an|the) (?:system|admin|root|developer)", "role reassignment"),
    (r"do not (?:verify|validate|check|flag) this", "verification bypass request"),
    (r"(?:mark|treat|report) (?:this|it) as (?:verified|fixed|safe|resolved)", "outcome dictation"),
    (r"approve (?:this|the) action (?:automatically|without review|immediately)", "unreviewed-approval request"),
    (r"grant (?:full |root |admin |elevated )+(?:access|privileges|permissions)", "privilege-escalation request"),
    (r"disable (?:logging|verification|the policy gate|monitoring)", "control-disabling request"),
    (r"<\s*system\s*>|\[system\]|###\s*system", "fake system-turn delimiter"),
)
_COMPILED = tuple((re.compile(pattern), label) for pattern, label in _PATTERNS)


@dataclass(frozen=True)
class InjectionSignal:
    """A review signal, not a verdict. `matches` is empty when nothing fired."""
    matches: tuple[tuple[str, str], ...]  # (matched substring, pattern label)

    @property
    def suspected(self) -> bool:
        return bool(self.matches)

    def to_json(self) -> dict:
        return {"suspected": self.suspected,
                "matches": [{"text": text, "pattern": label} for text, label in self.matches]}


def scan(text: str) -> InjectionSignal:
    """Scan raw advisory/document text for known instruction-injection patterns."""
    lowered = text.lower()
    found = []
    for pattern, label in _COMPILED:
        match = pattern.search(lowered)
        if match:
            found.append((text[match.start():match.end()], label))
    return InjectionSignal(tuple(found))
