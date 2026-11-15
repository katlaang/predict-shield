"""Test double for a language model: fixed replies chosen by a phrase in the prompt.

These replies are written by hand to exercise the checks around the model,
including replies a real model should never give. They are not model output.
"""
import json

from predict_shield.language_model import ModelUnavailable


class ScriptedModel:
    name = "scripted"

    def __init__(self, replies):
        self.replies, self.prompts = list(replies), []

    def complete(self, system, prompt):
        self.prompts.append(prompt)
        for phrase, reply in self.replies:
            if phrase in prompt:
                return reply if isinstance(reply, str) else json.dumps(reply)
        raise ModelUnavailable("scripted: no reply for this prompt")


def reading(package, fixed, introduced=None):
    return {"affected": [{"package": package, "ranges": [{"introduced": introduced, "fixed": fixed}]}]}
