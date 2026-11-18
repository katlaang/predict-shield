"""Unit tests for action_proposer.py, which had none."""
import json
import unittest

from predict_shield.action_proposer import ABSTAINED, ACCEPTED, REJECTED, ModelActionProposer, validate_reply
from scripted_model import ScriptedModel

OFFERED = ["upgrade_package", "pin_version"]


class ActionProposerTests(unittest.TestCase):
    def test_the_model_is_shown_exactly_the_offered_actions(self):
        model = ScriptedModel([("lodash", {"action": "upgrade_package", "rationale": "fixed upstream"})])
        proposal = ModelActionProposer(model).propose({"package": "lodash"}, OFFERED)
        self.assertEqual(json.loads(model.prompts[0])["permitted_actions"], OFFERED)
        self.assertEqual(proposal.status, ACCEPTED)

    def test_an_unoffered_action_is_rejected(self):
        self.assertEqual(validate_reply('{"action": "delete_repo", "rationale": "x"}', OFFERED).status, REJECTED)

    def test_no_offered_actions_abstains_without_calling_the_model(self):
        model = ScriptedModel([])
        self.assertEqual(ModelActionProposer(model).propose({"package": "lodash"}, []).status, ABSTAINED)
        self.assertEqual(model.prompts, [])


if __name__ == "__main__":
    unittest.main()
