import copy
import unittest

from reference_runtime.runtime import GovernanceRuntime
from validator.core import (
    ValidationError,
    digest,
    request_digest,
    sign_receipt_hmac,
    validate_action_receipt,
    validate_policy,
    validate_skill,
    validate_transition,
    verify_receipt_hmac,
)


SKILL = {
    "schema": "oat.skill/v1",
    "skill_id": "com.example.test",
    "version": "1.0.0",
    "artifact": {"uri": "file://skill", "digest": "sha256:bf0ec63b970d163d9ae2f54383a102f6a83a9d905f5ef4cf5ee809d855e26efa"},
    "publisher": {"id": "example.org"},
    "capabilities": {"action_classes": ["read", "write", "deploy"]},
}

POLICY = {
    "schema": "oat.policy/v1",
    "policy_id": "com.example.policy",
    "version": "1.0.0",
    "skill_ref": {"skill_id": SKILL["skill_id"], "version": SKILL["version"], "manifest_digest": digest(SKILL)},
    "action_classes": {
        "read": {"autonomy_state": "bounded_autonomous", "human_approval": "not_required"},
        "write": {"autonomy_state": "supervised", "human_approval": "required", "requires_exact_payload_digest": True},
        "deploy": {"autonomy_state": "revoked", "human_approval": "required"},
    },
}


class RuntimeTests(unittest.TestCase):
    def test_skill_manifest_validates(self):
        self.assertEqual(validate_skill(SKILL)["schema"], "oat.skill/v1")

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
        validate_action_receipt(decision.receipt)

    def test_write_requires_approval_then_releases(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        request = {"path": "app.py", "operation": "write"}
        self.assertEqual(runtime.check_action("write", request).status, "pending_review")
        decision = runtime.check_action("write", request, approved_by="reviewer")
        self.assertEqual(decision.status, "approved")
        validate_action_receipt(decision.receipt)

    def test_revoked_action_is_blocked_even_with_approval(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        decision = runtime.check_action("deploy", {"target": "prod"}, approved_by="cto")
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.receipt["decision"]["method"], "policy")

    def test_demotion_is_fail_safe_and_valid(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        transition = runtime.demote("write", "critical error")
        self.assertEqual(transition["to_state"], "observe")
        validate_transition(transition)

    def test_digest_is_stable(self):
        self.assertEqual(digest(SKILL), digest(dict(SKILL)))

    def test_payload_drift_changes_request_digest(self):
        original = {"path": "app.py", "operation": "write", "body": "safe"}
        changed = {"path": "app.py", "operation": "write", "body": "different"}
        self.assertNotEqual(request_digest(original), request_digest(changed))

    def test_signed_receipt_verifies(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        receipt = runtime.check_action("write", {"path": "app.py"}, approved_by="reviewer").receipt
        signed = sign_receipt_hmac(receipt, key_id="unit-test-key", secret=b"secret")
        self.assertTrue(verify_receipt_hmac(signed, secret_lookup={"unit-test-key": b"secret"}))

    def test_tampered_signed_receipt_fails_validation(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        receipt = runtime.check_action("write", {"path": "app.py"}, approved_by="reviewer").receipt
        signed = sign_receipt_hmac(receipt, key_id="unit-test-key", secret=b"secret")
        tampered = copy.deepcopy(signed)
        tampered["decision"]["reason"] = "changed after approval"
        with self.assertRaises(ValidationError):
            validate_action_receipt(tampered)

    def test_receipt_ids_are_not_reused_for_repeated_requests(self):
        runtime = GovernanceRuntime(SKILL, POLICY)
        first = runtime.check_action("read", {"path": "README.md"}).receipt
        second = runtime.check_action("read", {"path": "README.md"}).receipt
        self.assertNotEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(second["integrity"]["previous_receipt_digest"], first["integrity"]["receipt_digest"])


if __name__ == "__main__":
    unittest.main()
