"""Dependency-free checks for Open Agent Trust System profile documents.

The JSON Schemas are the interoperability contract. These checks add
runtime-facing invariants without requiring jsonschema or a signing service.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional


class ValidationError(ValueError):
    """Raised when a profile document violates a required invariant."""


SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
ACTION_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_:-]*$")
VALID_STATES = {
    "observe",
    "supervised",
    "act_with_approval",
    "bounded_autonomous",
    "revoked",
}
VALID_APPROVAL = {"required", "not_required"}
VALID_RECEIPT_STATUS = {"allowed", "pending_review", "approved", "blocked", "rejected"}
VALID_DECISION_METHOD = {"policy", "human", "system"}


def _required(document: Mapping[str, Any], names: Iterable[str]) -> None:
    missing = [name for name in names if name not in document]
    if missing:
        raise ValidationError("missing required fields: " + ", ".join(missing))


def _schema(document: Mapping[str, Any], expected: str) -> None:
    if document.get("schema") != expected:
        raise ValidationError(
            f"expected schema {expected!r}, got {document.get('schema')!r}"
        )


def _sha256(value: Any, field: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise ValidationError(f"{field} must be a sha256:<64 lowercase hex> digest")


def _action_class(value: Any, field: str) -> None:
    if not isinstance(value, str) or not ACTION_RE.match(value):
        raise ValidationError(f"{field} must be a valid action class")


def validate_document(document: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    """Validate the common shape of a profile document."""
    expected = {
        "skill": "oats.skill/v1",
        "policy": "oats.policy/v1",
        "attestation": "oats.attestation/v1",
        "action_receipt": "oats.action-receipt/v1",
        "transition": "oats.transition/v1",
    }.get(kind)
    if expected is None:
        raise ValidationError(f"unsupported document kind: {kind}")
    _schema(document, expected)
    return dict(document)


def validate_skill(skill: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a skill manifest's minimum portable identity."""
    validate_document(skill, "skill")
    _required(skill, ("skill_id", "version", "artifact", "publisher", "capabilities"))
    artifact = skill["artifact"]
    _required(artifact, ("uri", "digest"))
    _sha256(artifact["digest"], "artifact.digest")
    action_classes = skill["capabilities"].get("action_classes")
    if not isinstance(action_classes, list) or not action_classes:
        raise ValidationError("capabilities.action_classes must be a non-empty list")
    if len(action_classes) != len(set(action_classes)):
        raise ValidationError("capabilities.action_classes must be unique")
    for action_class in action_classes:
        _action_class(action_class, "capabilities.action_classes[]")
    return dict(skill)


def validate_policy(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a policy and its action-class autonomy invariants."""
    validate_document(policy, "policy")
    _required(policy, ("policy_id", "version", "skill_ref", "action_classes"))
    if not policy["action_classes"]:
        raise ValidationError("policy must define at least one action class")
    for action_class, definition in policy["action_classes"].items():
        _action_class(action_class, "action_classes key")
        _required(definition, ("autonomy_state", "human_approval"))
        state = definition.get("autonomy_state")
        approval = definition.get("human_approval")
        if state not in VALID_STATES:
            raise ValidationError(
                f"{action_class}: unsupported autonomy state {state!r}"
            )
        if approval not in VALID_APPROVAL:
            raise ValidationError(
                f"{action_class}: unsupported human approval rule {approval!r}"
            )
        if state == "bounded_autonomous" and approval == "required":
            raise ValidationError(
                f"{action_class}: bounded_autonomous cannot require per-action approval"
            )
    return dict(policy)


def validate_action_receipt(receipt: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate receipt integrity fields and digest binding."""
    validate_document(receipt, "action_receipt")
    _required(receipt, ("receipt_id", "skill_ref", "action", "policy_ref", "autonomy", "decision", "timestamps", "integrity"))
    _sha256(receipt["skill_ref"].get("manifest_digest"), "skill_ref.manifest_digest")
    _action_class(receipt["action"].get("class"), "action.class")
    _sha256(receipt["action"].get("request_digest"), "action.request_digest")
    _sha256(receipt["policy_ref"].get("digest"), "policy_ref.digest")
    state = receipt["autonomy"].get("state")
    if state not in VALID_STATES:
        raise ValidationError(f"autonomy.state unsupported: {state!r}")
    decision = receipt["decision"]
    if decision.get("status") not in VALID_RECEIPT_STATUS:
        raise ValidationError(f"decision.status unsupported: {decision.get('status')!r}")
    if decision.get("method") not in VALID_DECISION_METHOD:
        raise ValidationError(f"decision.method unsupported: {decision.get('method')!r}")
    _sha256(receipt["integrity"].get("receipt_digest"), "integrity.receipt_digest")
    expected = receipt_digest(receipt)
    if receipt["integrity"]["receipt_digest"] != expected:
        raise ValidationError("integrity.receipt_digest does not match receipt content")
    signature = receipt.get("signature")
    if signature is not None:
        _required(signature, ("algorithm", "key_id", "value"))
    return dict(receipt)


def validate_transition(transition: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a lifecycle/autonomy transition."""
    validate_document(transition, "transition")
    _required(transition, ("transition_id", "skill_ref", "action_class", "from_state", "to_state", "evidence", "authorization", "scope", "status", "occurred_at", "integrity"))
    _action_class(transition["action_class"], "action_class")
    if transition["from_state"] not in VALID_STATES or transition["to_state"] not in VALID_STATES:
        raise ValidationError("transition states must be valid autonomy states")
    if transition["from_state"] == transition["to_state"]:
        raise ValidationError("transition must change state")
    _required(transition["evidence"], ("trigger",))
    _required(transition["authorization"], ("authorized",))
    _required(transition["scope"], ("effect",))
    _sha256(transition["integrity"].get("transition_digest"), "integrity.transition_digest")
    expected = document_digest(transition, omit_integrity_field="transition_digest")
    if transition["integrity"]["transition_digest"] != expected:
        raise ValidationError("integrity.transition_digest does not match transition content")
    return dict(transition)


def canonical_json(document: Mapping[str, Any]) -> bytes:
    """Return stable JSON bytes suitable for hashing."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unsigned_copy(document: Mapping[str, Any], *, omit_integrity_field: Optional[str] = None) -> Dict[str, Any]:
    copied = json.loads(json.dumps(document))
    copied.pop("signature", None)
    if omit_integrity_field and isinstance(copied.get("integrity"), dict):
        copied["integrity"].pop(omit_integrity_field, None)
    return copied


def document_digest(document: Mapping[str, Any], *, omit_integrity_field: Optional[str] = None) -> str:
    """Hash a document, omitting signatures and optionally self-digest fields."""
    return "sha256:" + hashlib.sha256(
        canonical_json(_unsigned_copy(document, omit_integrity_field=omit_integrity_field))
    ).hexdigest()


def digest(document: Mapping[str, Any]) -> str:
    """Backward-compatible helper for hashing unsigned documents."""
    return document_digest(document)


def request_digest(request: Mapping[str, Any]) -> str:
    """Hash an exact action request payload."""
    return "sha256:" + hashlib.sha256(canonical_json(request)).hexdigest()


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    """Hash a receipt without its self-referential receipt_digest or signature."""
    return document_digest(receipt, omit_integrity_field="receipt_digest")


def transition_digest(transition: Mapping[str, Any]) -> str:
    """Hash a transition without its self-referential transition_digest."""
    return document_digest(transition, omit_integrity_field="transition_digest")


def sign_receipt_hmac(receipt: Mapping[str, Any], *, key_id: str, secret: bytes) -> Dict[str, Any]:
    """Attach a demonstrative HMAC signature over the receipt digest.

    Production envelopes can use DSSE, Sigstore, KMS, or workload identity. HMAC
    keeps the reference package dependency-free and testable.
    """
    validate_action_receipt(receipt)
    value = hmac.new(secret, receipt["integrity"]["receipt_digest"].encode("utf-8"), hashlib.sha256).hexdigest()
    signed = json.loads(json.dumps(receipt))
    signed["signature"] = {"algorithm": "HMAC-SHA256", "key_id": key_id, "value": value}
    return signed


def verify_receipt_hmac(receipt: Mapping[str, Any], *, secret_lookup: Mapping[str, bytes]) -> bool:
    """Verify the demonstrative HMAC signature on a receipt."""
    validate_action_receipt(receipt)
    signature = receipt.get("signature")
    if not signature or signature.get("algorithm") != "HMAC-SHA256":
        return False
    secret = secret_lookup.get(signature["key_id"])
    if secret is None:
        return False
    expected = hmac.new(secret, receipt["integrity"]["receipt_digest"].encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature["value"])
