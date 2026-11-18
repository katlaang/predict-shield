"""Unit tests for script_risk_proposer.py: constrained AI containment choice."""
import unittest

from predict_shield.script_risk_proposer import (
    ACCEPTED,
    ABSTAINED,
    REJECTED,
    ModelScriptRiskProposer,
    validate_reply,
)
from scripted_model import ScriptedModel

OFFERED = ["block_via_csp", "revoke_sri_pin", "disable_embed"]


class ValidateReplyTests(unittest.TestCase):
    def test_an_offered_action_is_accepted(self):
        proposal = validate_reply('{"severity": "high", "action": "block_via_csp", "rationale": "contain"}', OFFERED)
        self.assertEqual(proposal.status, ACCEPTED)
        self.assertEqual(proposal.action_id, "block_via_csp")

    def test_a_null_action_abstains(self):
        proposal = validate_reply('{"severity": "high", "action": null, "rationale": "insufficient evidence"}', OFFERED)
        self.assertEqual(proposal.status, ABSTAINED)

    def test_an_action_not_in_the_offered_list_is_rejected_not_accepted(self):
        proposal = validate_reply('{"severity": "high", "action": "wipe_the_database", "rationale": "..."}', OFFERED)
        self.assertEqual(proposal.status, REJECTED)
        self.assertIsNone(proposal.action_id)

    def test_malformed_json_is_rejected(self):
        proposal = validate_reply("not json at all", OFFERED)
        self.assertEqual(proposal.status, REJECTED)

    def test_the_models_severity_assessment_is_recorded(self):
        proposal = validate_reply('{"severity": "Critical", "action": "block_via_csp", "rationale": "x"}', OFFERED)
        self.assertEqual(proposal.severity, "critical")

    def test_a_missing_or_invented_severity_is_rejected(self):
        for reply in ('{"action": "block_via_csp", "rationale": "x"}',
                      '{"severity": "catastrophic", "action": "block_via_csp", "rationale": "x"}'):
            proposal = validate_reply(reply, OFFERED)
            self.assertEqual(proposal.status, REJECTED)
            self.assertIsNone(proposal.action_id)


class ModelScriptRiskProposerTests(unittest.TestCase):
    def test_a_normal_reply_proposes_an_offered_action(self):
        model = ScriptedModel([("widget", {"severity": "high", "action": "block_via_csp", "rationale": "hash mismatch"})])
        proposer = ModelScriptRiskProposer(model)
        proposal = proposer.propose({"script_id": "widget"}, OFFERED)
        self.assertEqual(proposal.status, ACCEPTED)
        self.assertEqual(proposal.action_id, "block_via_csp")
        self.assertFalse(proposal.injection_suspected)

    def test_no_offered_actions_abstains_without_calling_the_model(self):
        model = ScriptedModel([])
        proposer = ModelScriptRiskProposer(model)
        proposal = proposer.propose({"script_id": "widget"}, [])
        self.assertEqual(proposal.status, ABSTAINED)
        self.assertEqual(model.prompts, [])


if __name__ == "__main__":
    unittest.main()
