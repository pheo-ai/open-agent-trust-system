import unittest

from reference_runtime.runtime import GovernanceRuntime
from validator.core import ValidationError, digest, validate_policy


SKILL = {
    "schema": "stl.skill/v1",
    "skill_id": "com.example.test",
    "version": "1.0.0",
    "artifact": {"uri": "file://skill", "digest": "sha256:test"},
    "publisher": {"id": "example.org"},
    "capabilities": {"action_classes": ["read", "write"]},
}

POLICY = {
    "schema": "stl.policy/v1",
    "policy_id": "com.example.policy",
    "version": "1.0.0",
    "skill_ref": {"skill_id": SKILL["skill_id"], "version": SKILL["version"]},
    "action_classes": {
        "read": {"autonomy_state": "bounded_autonomous", "human_approval": "not_required"},
        "write": {"autonomy_state": "supervised", "human_approval": "required"},
    },
}


class RuntimeTests(unittest.TestCase):
    def test_policy_rejects_approval_required_autonomy(self):
        invalid = {**POLICY, "action_classes": {
            "write": {"autonomy_state": "bounded_autonomous", "human_approval": "required"}
        }}
        with self.assertRaises(ValidationError):
            validate_policy(invalid)

    def test_read_is_allowed_without_approval(self):
        decision = GovernanceRuntime(SKILL, POLICY).check_action("read", {"path": "README.md"})
        self.assertEqual(decision.status, "allowed")
        self.assertTrue(decision.receipt["integrity"]["receipt_digest"].startswith("sha256:"))

    def test_write_requires_approval_then_releases(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        request = {"path": "app.py", "operation": "write"}
        self.assertEqual(runtime.check_action("write", request).status, "pending_review")
        decision = runtime.check_action("write", request, approved_by="reviewer")
        self.assertEqual(decision.status, "approved")

    def test_revoked_action_is_blocked(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        runtime.state["write"] = "revoked"
        self.assertEqual(runtime.check_action("write", {}).status, "blocked")

    def test_demotion_is_fail_safe(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        transition = runtime.demote("write", "critical error")
        self.assertEqual(transition["to_state"], "supervised")

    def test_digest_is_stable(self):
        self.assertEqual(digest(SKILL), digest(dict(SKILL)))


if __name__ == "__main__":
    unittest.main()
