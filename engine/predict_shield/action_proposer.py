"""Model choice of the response action, inside the limits the gate has set.

Order of control in a decision:

    1. The action gate removes every action that is prohibited, needs human
       approval, lacks an impact estimate or would exceed a service's remaining
       error budget.
    2. The pipeline keeps the permitted actions whose estimated residual risk is
       close to the best one.
    3. The model chooses among those, seeing what was tried earlier in the case
       and what the verifier found afterwards.

The model therefore cannot select an action the policy forbids, and cannot
choose to do nothing when an effective action is permitted. Its reply is
checked here: the action must be one of the offered ones. Anything else is
refused and the scoring formula's choice stands.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from .language_model import LanguageModel, ModelUnavailable, parse_json_object

ACCEPTED, ABSTAINED, REJECTED = "ACCEPTED", "ABSTAINED", "REJECTED"
MAX_RATIONALE_CHARS = 600


@dataclass(frozen=True)
class Proposal:
    status: str
    action_id: str | None
    rationale: str = ""
    reasons: tuple[str, ...] = ()


class ActionProposer(Protocol):
    name: str

    def propose(self, context: dict, offered: list[str]) -> Proposal: ...


SYSTEM_PROMPT = """You choose the response action for a vulnerability remediation case.
You are given the case state and a list of permitted actions. Policy checks have already been applied, so every listed action is allowed.
Choose the action most likely to leave no affected instance, with the least disruption to services. Take earlier actions in this case into account: an action that left an instance affected is unlikely to fix that instance if repeated.

Reply with one JSON object and nothing else:
{"action": "<one action copied exactly from permitted_actions>", "rationale": "<one or two sentences>"}
If you cannot choose, reply {"action": null, "rationale": "<why>"}."""


def validate_reply(reply: str, offered: list[str]) -> Proposal:
    try:
        data = parse_json_object(reply)
    except ValueError as error:
        return Proposal(REJECTED, None, reasons=(f"reply is not valid JSON: {error}",))
    action, rationale = data.get("action"), data.get("rationale", "")
    rationale = rationale[:MAX_RATIONALE_CHARS] if isinstance(rationale, str) else ""
    if action is None:
        return Proposal(ABSTAINED, None, rationale, ("model made no choice",))
    if not isinstance(action, str) or action not in offered:
        return Proposal(REJECTED, None, rationale, (f"action not among the offered ones: {action!r}",))
    return Proposal(ACCEPTED, action, rationale)


class ModelActionProposer:
    def __init__(self, model: LanguageModel):
        self.model, self.name = model, "model:" + model.name

    def propose(self, context: dict, offered: list[str]) -> Proposal:
        if not offered:
            return Proposal(ABSTAINED, None, reasons=("no action offered",))
        try:
            reply = self.model.complete(SYSTEM_PROMPT, json.dumps(context, indent=1, sort_keys=True))
        except ModelUnavailable as error:
            return Proposal(ABSTAINED, None, reasons=(f"model unavailable: {error}",))
        return validate_reply(reply, offered)
