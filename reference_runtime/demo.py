"""Run the coding-agent reference scenario."""

from __future__ import annotations

from validator.core import digest
from reference_runtime.runtime import GovernanceRuntime


SKILL = {
    "schema": "stl.skill/v1",
    "skill_id": "com.example.coding-agent",
    "version": "0.1.0",
    "artifact": {"uri": "file://./skill", "digest": "sha256:demo"},
    "publisher": {"id": "example.org"},
    "capabilities": {
        "action_classes": ["read_files", "propose_patch", "apply_patch", "commit", "deploy"]
    },
}

POLICY = {
    "schema": "stl.policy/v1",
    "policy_id": "com.example.coding-agent-policy",
    "version": "1.0.0",
    "skill_ref": {"skill_id": SKILL["skill_id"], "version": SKILL["version"]},
    "action_classes": {
        "read_files": {"autonomy_state": "bounded_autonomous", "human_approval": "not_required"},
        "propose_patch": {"autonomy_state": "supervised", "human_approval": "required"},
        "apply_patch": {"autonomy_state": "act_with_approval", "human_approval": "required"},
        "commit": {"autonomy_state": "act_with_approval", "human_approval": "required"},
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
    transition = runtime.demote("propose_patch", "critical test failure")
    print(
        "demotion emitted: "
        f"{transition['action_class']} {transition['from_state']} -> {transition['to_state']}"
    )
    if last_receipt:
        print(f"receipt digest created: {last_receipt['integrity']['receipt_digest']}")
    print(f"manifest digest: {digest(SKILL)}")


if __name__ == "__main__":
    main()
