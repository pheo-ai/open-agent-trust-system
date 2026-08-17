"""Run the coding-agent reference scenario."""

from __future__ import annotations

from validator.core import digest, sign_receipt_hmac, validate_action_receipt, validate_transition
from reference_runtime.runtime import GovernanceRuntime


SKILL = {
    "schema": "oats.skill/v1",
    "skill_id": "com.example.coding-agent",
    "version": "0.1.0",
    "artifact": {"uri": "file://./skill", "digest": "sha256:89726b6a862b095593c49029534231a074a01c835ed0766705b866d5239f94a5"},
    "publisher": {"id": "example.org"},
    "capabilities": {
        "action_classes": ["read_files", "propose_patch", "apply_patch", "commit", "deploy"]
    },
}

POLICY = {
    "schema": "oats.policy/v1",
    "policy_id": "com.example.coding-agent-policy",
    "version": "1.0.0",
    "skill_ref": {"skill_id": SKILL["skill_id"], "version": SKILL["version"], "manifest_digest": digest(SKILL)},
    "action_classes": {
        "read_files": {"autonomy_state": "bounded_autonomous", "human_approval": "not_required"},
        "propose_patch": {"autonomy_state": "supervised", "human_approval": "required"},
        "apply_patch": {"autonomy_state": "act_with_approval", "human_approval": "required", "requires_exact_payload_digest": True},
        "commit": {"autonomy_state": "act_with_approval", "human_approval": "required", "requires_exact_payload_digest": True},
        "deploy": {"autonomy_state": "revoked", "human_approval": "required"},
    },
}


def main() -> None:
    runtime = GovernanceRuntime(SKILL, POLICY)
    last_receipt = None
    for action in ("read_files", "propose_patch", "apply_patch", "commit", "deploy"):
        request = {"repository": "sandbox", "action": action}
        pending = runtime.check_action(action, request)
        print(f"{action}: {pending.status}")
        last_receipt = pending.receipt
        if pending.status == "pending_review":
            approved = runtime.check_action(
                action,
                request,
                approved_by="developer@example.org",
                reason="Reviewed exact payload and approved release.",
            )
            print(f"{action}: pending_review -> {approved.status}")
            last_receipt = approved.receipt
    transition = runtime.demote("apply_patch", "critical test failure")
    validate_transition(transition)
    print(
        "demotion emitted: "
        f"{transition['action_class']} {transition['from_state']} -> {transition['to_state']}"
    )
    if last_receipt:
        signed = sign_receipt_hmac(last_receipt, key_id="demo-review-key", secret=b"open-agent-trust-system-demo")
        validate_action_receipt(signed)
        print(f"receipt digest created: {signed['integrity']['receipt_digest']}")
        print(f"receipt signature: {signed['signature']['algorithm']} {signed['signature']['key_id']}")


if __name__ == "__main__":
    main()
