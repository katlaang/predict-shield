"""Prospective design tests only, not physical outcomes."""
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from persistent_ai_plan import build,validate,COUNTS,FAULTS,STRATA
from run_persistent_five_pilot import evaluate_results


class FiveFamilyPilotTests(unittest.TestCase):
    def test_balanced_five_independent_faults_and_strata(self):
        c,t=build()
        self.assertEqual(build(),(c,t))
        self.assertEqual((len(c),len(t)),(30,240))
        self.assertEqual(Counter(x["partition"] for x in c),COUNTS)
        self.assertEqual(Counter(x["fault_mode"] for x in c),dict.fromkeys(FAULTS,6))
        self.assertEqual(Counter(x["complexity_stratum"] for x in c),
                         dict.fromkeys(STRATA,10))
        self.assertTrue(all(x["execution_status"]=="PLANNED_NOT_EXECUTED" for x in t))
        self.assertNotIn("authority_outage",set(x["fault_mode"] for x in c))

    def test_missing_physical_replay_is_rejected(self):
        c,t=build()
        with self.assertRaises(ValueError):validate(c,t[:-1])

    def test_model_not_trained_from_an_empty_record_directory(self):
        c,t=build()
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,"Unverified physical action"):
                evaluate_results(c,t,Path(folder))

    def test_no_false_completed_trial_in_manifest(self):
        c,t=build()
        t[0]["execution_status"]="COMPLETE"
        with self.assertRaises(ValueError):validate(c,t)


if __name__=="__main__":
    unittest.main()
