"""Small dependency-free checks for the reference profile.

The schemas are the interoperability contract. These checks add actionable
runtime invariants without requiring jsonschema or a signing service.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, Mapping


class ValidationError(ValueError):
    """Raised when a profile document violates a required invariant."""


def _required(document: Mapping[str, Any], names: Iterable[str]) -> None:
    missing = [name for name in names if name not in document]
    if missing:
        raise ValidationError("missing required fields: " + ", ".join(missing))


def _schema(document: Mapping[str, Any], expected: str) -> None:
    if document.get("schema") != expected:
        raise ValidationError(
            f"expected schema {expected!r}, got {document.get('schema')!r}"
        )


def validate_document(document: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    """Validate the common shape of a profile document."""
    expected = {
        "skill": "oat.skill/v1",
        "policy": "oat.policy/v1",
        "attestation": "oat.attestation/v1",
        "action_receipt": "oat.action-receipt/v1",
        "transition": "oat.transition/v1",
    }.get(kind)
    if expected is None:
        raise ValidationError(f"unsupported document kind: {kind}")
    _schema(document, expected)
    return dict(document)


def validate_policy(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a policy and its action-class autonomy invariants."""
    validate_document(policy, "policy")
    _required(policy, ("policy_id", "version", "skill_ref", "action_classes"))
    if not policy["action_classes"]:
        raise ValidationError("policy must define at least one action class")
    valid_states = {
        "observe",
        "supervised",
        "act_with_approval",
        "bounded_autonomous",
        "revoked",
    }
    for action_class, definition in policy["action_classes"].items():
        state = definition.get("autonomy_state")
        if state not in valid_states:
            raise ValidationError(
                f"{action_class}: unsupported autonomy state {state!r}"
            )
        if state == "bounded_autonomous" and definition.get("human_approval") == "required":
            raise ValidationError(
                f"{action_class}: bounded_autonomous cannot require per-action approval"
            )
    return dict(policy)


def canonical_json(document: Mapping[str, Any]) -> bytes:
    """Return stable JSON bytes suitable for hashing."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(document: Mapping[str, Any]) -> str:
    """Hash a document without a signature field."""
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    return "sha256:" + hashlib.sha256(canonical_json(unsigned)).hexdigest()
