"""No-network tests for resuming and auditing a measured Experiment B campaign."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from audit import audit_campaign
from campaign import exclusive_lock, next_trials, register_plan
from plan import create_plan


class CampaignTests(unittest.TestCase):
    """Prevent overlapping campaigns, altered plans and unsafe resumption."""

    def setUp(self):
        """Create a reproducible plan and empty temporary on-disk campaign."""
        self.cfg, self.trials = create_plan()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_registration_is_stable_and_rejects_modified_protocol(self):
        """The same plan can resume but a revised plan must use new storage."""
        digest = register_plan(self.root, self.cfg, self.trials)
        self.assertEqual(digest, register_plan(self.root, self.cfg, self.trials))
        modified = [dict(c) for c in self.cfg]
        modified[0]["cache_ttl_ms"] += 1
        with self.assertRaises(ValueError):
            register_plan(self.root, modified, self.trials)

    def test_resume_chooses_only_missing_trial_ids(self):
        """A new campaign starts with exactly its declared first bounded batch."""
        work = next_trials(self.trials, self.root, max_trials=4, resume=True)
        self.assertEqual([t["run_id"] for t in work],
                         [t["run_id"] for t in self.trials[:4]])
        self.assertEqual(len(work), 4)

    def test_partial_trial_aborts_instead_of_reusing(self):
        """Partial oracle or operational outcomes must not be fabricated."""
        first = self.trials[0]["run_id"]
        folder = self.root / "pre_action"
        folder.mkdir()
        (folder / (first + ".json")).write_text("{}")
        with self.assertRaises(RuntimeError):
            next_trials(self.trials, self.root, max_trials=4, resume=True)

    def test_lock_excludes_simultaneous_writer(self):
        """Two collectors cannot reset the same stateful JVMs concurrently."""
        with exclusive_lock(self.root):
            with self.assertRaises(FileExistsError):
                with exclusive_lock(self.root):
                    pass
        self.assertFalse((self.root / ".campaign.lock").exists())

    def test_invalid_batch_limits_are_rejected(self):
        """Any run must have a bounded explicit range."""
        for value in (0, -1, 13, 1200):
            with self.assertRaises(ValueError):
                next_trials(self.trials, self.root, max_trials=value)
        with self.assertRaises(ValueError):
            next_trials(self.trials, self.root, start=1200)

    def test_audit_is_observational_only(self):
        """Calling the audit does not create labels, files or Docker operations."""
        before = set(self.root.iterdir())
        results = audit_campaign(self.cfg, self.trials, self.root)
        self.assertEqual(before, set(self.root.iterdir()))
        self.assertEqual(results["complete"], 0)
        self.assertEqual(results["missing"], 1200)


if __name__ == "__main__":
    unittest.main()
