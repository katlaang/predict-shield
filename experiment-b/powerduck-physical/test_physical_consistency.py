import math
import unittest

from physical_consistency import PairSpec, aligned, score, train


SPEC = PairSpec("breaker>bus", "current_A", "meter>bus", "current_A", 0.06)


def trace(n=300, attack_at=None, break_reference=False):
    events = []
    for i in range(n):
        t = i * 0.2
        x = 3 + 1.7 * math.sin(i / 11)
        events.append({"timestamp": t - 0.02, "src": "meter", "dest": "bus",
                       "data": {"current_A": x}})
        events.append({"timestamp": t, "src": "breaker", "dest": "bus",
                       "data": {"current_A": (50.0 if i == attack_at else 2 * x + 1)},
                       "malicious": "tampered" if i == attack_at else None})
    if break_reference:
        events = [r for r in events if r["src"] != "meter"]
    return events


class PhysicalRelationshipTests(unittest.TestCase):
    def test_learn_normal_and_flag_cross_stream_inconsistency(self):
        frozen, dev = train(trace(), SPEC)
        self.assertEqual(dev["paired_rows"], 300)
        self.assertLessEqual(dev["normal_calibration_alert_rate"], 0.01)
        result = score(trace(300, attack_at=180), frozen)
        self.assertEqual(result["primary_attack_labeled"], 1)
        self.assertEqual(result["primary_attack_alerts"], 1)
        self.assertIsNone(result["normal_false_positive_rate"])

    def test_missing_primary_measurement_is_indeterminate_not_dropped(self):
        example = trace()
        example[1]["data"].pop("current_A")
        frozen, _ = train(trace(), SPEC)
        scored = score(example, frozen)
        self.assertEqual(scored["total_primary_messages"], 300)
        self.assertEqual(scored["indeterminate"], 1)
        self.assertEqual(scored["events"][0]["reason"], "missing_primary_measurement")

    def test_missing_malicious_primary_still_audited_as_missing(self):
        example = trace()
        example[1]["data"].pop("current_A")
        example[1]["malicious"] = "labeled"
        frozen, _ = train(trace(), SPEC)
        scored = score(example, frozen)
        self.assertEqual(scored["indeterminate"], 1)
        self.assertEqual(scored["events"][0]["truth"], "ATTACK_LABELED_PRIMARY")

    def test_no_reference_abstains(self):
        spec = PairSpec("breaker>bus", "current_A", "meter>bus", "current_A")
        result = aligned(trace(2, break_reference=True), spec)
        self.assertTrue(all(r["truth"] == "INDETERMINATE" for r in result))

    def test_no_physical_association_must_fail(self):
        with self.assertRaises(ValueError):
            train(trace(3), SPEC)

    def test_same_stream_rejected(self):
        with self.assertRaises(ValueError):
            PairSpec("x", "foo", "x", "bar").check()

    def test_tampered_freeze_rejected(self):
        frozen, _ = train(trace(), SPEC)
        frozen["slope"] = 0.01
        with self.assertRaises(ValueError):
            score(trace(), frozen)

    def test_reference_context_not_primary_truth(self):
        events = trace()
        events[0]["malicious"] = "reference-attack"
        frozen, _ = train(trace(), SPEC)
        scored = score(events, frozen)
        self.assertEqual(scored["primary_attack_labeled"], 0)


if __name__ == "__main__":
    unittest.main()
