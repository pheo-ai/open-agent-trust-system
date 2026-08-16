"""Minimal policy gate and hash-linked receipt runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from validator.core import canonical_json, digest, validate_policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Decision:
    status: str
    action_class: str
    reason: str
    receipt: Dict[str, Any]


class GovernanceRuntime:
    """A deliberately small reference implementation.

    It does not execute tools. It decides whether an external executor may
    proceed and emits evidence for that decision.
    """

    def __init__(self, skill: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
        validate_policy(policy)
        self.skill = dict(skill)
        self.policy = dict(policy)
        self.state = {
            action_class: definition["autonomy_state"]
            for action_class, definition in policy["action_classes"].items()
        }
        self.previous_receipt_digest: Optional[str] = None

    def check_action(
        self,
        action_class: str,
        request: Mapping[str, Any],
        *,
        approved_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Decision:
        definition = self.policy["action_classes"].get(action_class)
        if definition is None:
            return self._decision(action_class, "blocked", "action class is not declared", request)

        state = self.state[action_class]
        if state in {"observe", "revoked"}:
            return self._decision(action_class, "blocked", f"state is {state}", request)

        approval_required = (
            definition.get("human_approval") == "required"
            or state in {"supervised", "act_with_approval"}
        )
        if approval_required and not approved_by:
            return self._decision(
                action_class, "pending_review", "human approval is required", request
            )

        status = "approved" if approved_by else "allowed"
        return self._decision(
            action_class, status, reason or "policy permits this action", request,
            approved_by=approved_by,
        )

    def demote(self, action_class: str, trigger: str) -> Dict[str, Any]:
        if action_class not in self.state:
            raise KeyError(action_class)
        before = self.state[action_class]
        self.state[action_class] = "supervised"
        return {
            "schema": "stl.transition/v1",
            "transition_id": f"transition-{action_class}-{len(trigger)}",
            "skill_ref": {
                "skill_id": self.skill["skill_id"],
                "version": self.skill["version"],
            },
            "action_class": action_class,
            "from_state": before,
            "to_state": "supervised",
            "reason": {"trigger": trigger},
            "authorized": False,
            "occurred_at": _now(),
        }

    def _decision(
        self,
        action_class: str,
        status: str,
        reason: str,
        request: Mapping[str, Any],
        *,
        approved_by: Optional[str] = None,
    ) -> Decision:
        receipt = {
            "schema": "stl.action-receipt/v1",
            "receipt_id": f"receipt-{action_class}-{status}",
            "skill_ref": {
                "skill_id": self.skill["skill_id"],
                "version": self.skill["version"],
                "manifest_digest": digest(self.skill),
            },
            "action": {
                "class": action_class,
                "request_digest": "sha256:" + __import__("hashlib").sha256(
                    canonical_json(request)
                ).hexdigest(),
            },
            "policy_ref": {
                "policy_id": self.policy["policy_id"],
                "version": self.policy["version"],
                "digest": digest(self.policy),
            },
            "autonomy": {"state": self.state.get(action_class)},
            "decision": {
                "status": status,
                "method": "human" if approved_by else "policy",
                "approver_id": approved_by,
                "reason": reason,
            },
            "timestamps": {"decided_at": _now()},
            "integrity": {
                "previous_receipt_digest": self.previous_receipt_digest,
            },
        }
        receipt["integrity"]["receipt_digest"] = digest(receipt)
        self.previous_receipt_digest = receipt["integrity"]["receipt_digest"]
        return Decision(status, action_class, reason, receipt)
