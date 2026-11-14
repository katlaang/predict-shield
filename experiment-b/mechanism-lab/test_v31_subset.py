"""V3.1 subset registration and physical cleanup contract tests."""
import unittest
from unittest.mock import patch

import pilot_v31_plan as plan
from run_v31_subset import resume_all


class V31SubsetTests(unittest.TestCase):
    def test_registered_groups_and_trials(self):
        configs, trials=plan.create()
        self.assertEqual((len(configs),len(trials)),(5,40))
        self.assertEqual(len({t["run_id"] for t in trials}),40)
        self.assertTrue(all(c["partition"]=="pilot" for c in configs))
        self.assertEqual({c["fault_mode"] for c in configs},
                         {"loss","delay","duplicate","reorder","consumer_paused"})
        self.assertFalse(any(c["fault_mode"]=="authority_outage" for c in configs))
        self.assertEqual((configs,trials),plan.create())

    def test_registered_plan_rejects_claimed_execution(self):
        configs,trials=plan.create()
        trials[0]["execution_status"]="EXECUTED"
        with self.assertRaises(ValueError):
            plan.validate(configs,trials)

    @patch("run_v31_subset.request")
    def test_resume_reports_live_listener_state(self, request):
        request.side_effect = [(200,{},1),(200,{"container_paused":False},1)] * 4
        resume_all("a" * 32)
        self.assertEqual(request.call_count,8)

    def test_same_credentials_never_launch_physical_pilot(self):
        from run_v31_subset import execute
        from pathlib import Path
        with self.assertRaises(ValueError):
            execute("x"*32,"x"*32,Path("/tmp/unreachable-pilot"))


if __name__ == "__main__":
    unittest.main()
