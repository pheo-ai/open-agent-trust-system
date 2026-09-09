"""The published class spec is the auditable half of the resolver.

An auditor cannot read the predicates, so what spec/action-classes.json says
about the class set, the severity order, and which classes may graduate is the
only part of rho's behaviour that can be checked from outside. These tests
hold it to its own invariants so it cannot drift silently.
"""
import json
import pathlib
import unittest

SPEC = pathlib.Path(__file__).resolve().parent.parent / "spec" / "action-classes.json"


class ActionClassSpecTests(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads(SPEC.read_text())

    def test_has_the_documented_number_of_classes(self):
        self.assertEqual(len(self.rows), 33)

    def test_keys_and_labels_are_unique(self):
        keys = [r["key"] for r in self.rows]
        labels = [r["label"] for r in self.rows]
        self.assertEqual(len(set(keys)), len(keys))
        # Labels are what the hook emits, and measurement code maps them back
        # to keys. A duplicate label would make that mapping ambiguous.
        self.assertEqual(len(set(labels)), len(labels))

    def test_every_row_is_complete_and_well_typed(self):
        for r in self.rows:
            self.assertEqual(set(r), {"key", "label", "severity", "graduates"})
            self.assertIsInstance(r["key"], str)
            self.assertIsInstance(r["label"], str)
            self.assertIsInstance(r["graduates"], bool)
            self.assertIsInstance(r["severity"], int)
            self.assertTrue(0 <= r["severity"] <= 100)

    def test_graduation_is_a_severity_threshold_not_a_list(self):
        """Every class at severity 75 or above never graduates, and none below."""
        for r in self.rows:
            self.assertEqual(r["graduates"], r["severity"] < 75,
                             "%s: severity %d, graduates=%s"
                             % (r["key"], r["severity"], r["graduates"]))

    def test_thirteen_classes_never_graduate(self):
        self.assertEqual(sum(1 for r in self.rows if not r["graduates"]), 13)

    def test_the_classes_the_paper_names_as_never_graduating_are_present(self):
        never = {r["key"] for r in self.rows if not r["graduates"]}
        for key in ("shell_remote_exec", "shell_credential_access",
                    "shell_destructive", "secret_change", "deploy",
                    "iam_change", "modify_github_actions", "manage_webhook",
                    "delete_or_transfer_repo"):
            self.assertIn(key, never)


if __name__ == "__main__":
    unittest.main()
