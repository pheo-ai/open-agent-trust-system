# Specification Overview

## Scope

The OpenSharing Skill Trust & Lifecycle Profile adds portable trust and lifecycle metadata to shared AI skills. It is intended to compose with OpenSharing `AgentSkill` assets, MCP tool boundaries, and provenance systems such as DSSE, in-toto, SLSA, and Sigstore.

The profile standardizes evidence for authority decisions. It does not standardize agent reasoning, model behavior, marketplace operations, or enterprise enforcement UX.

## Object model

- `SkillManifest` identifies a skill artifact, publisher, version, digest, and declared action classes.
- `AutonomyPolicy` defines the allowed autonomy state and oversight rule for each action class.
- `LifecycleAttestation` records provenance, publication status, and lifecycle events for a skill release.
- `ActionReceipt` records a governed action request, its policy context, decision, payload digest, and receipt digest.
- `AutonomyTransition` records evidence-backed state changes for one skill action class.

## Lifecycle states

```text
observe -> supervised -> act_with_approval -> bounded_autonomous
    ^          ^                 ^                    |
    +----------+-----------------+--------------------+
                 demotion / rollback
```

- `observe`: the skill may be inspected but cannot act.
- `supervised`: every output/action requires human review before release.
- `act_with_approval`: the skill may prepare actions but execution requires exact-payload approval.
- `bounded_autonomous`: the skill may execute within policy limits and produces receipts.
- `revoked`: the skill cannot act until explicitly restored by a new approval process.

Implementations must apply autonomy per action class. A skill may be autonomous for reversible reads while remaining supervised for writes or deployments.

## Action receipt semantics

An `ActionReceipt` records the governed decision for a single action request. It must bind together:

- skill identity and manifest digest
- action class and request digest
- policy identity and policy digest
- current autonomy state
- decision status, method, reason, and optional approver
- timestamp and receipt digest

The request digest enables exact-payload approval. If the payload changes, the previous approval no longer applies.

## Transition semantics

An `AutonomyTransition` records a promotion, demotion, rollback, or revocation. Promotion requires explicit authorization. Demotion should be fail-safe and may be triggered automatically by policy violation, critical failure, drift, or elevated correction rate.

## Security and privacy

Portable profile documents should contain references and digests by default. They should not require raw customer data, private prompts, source code, research text, invoices, or personal data.

Implementations may wrap documents in established signing and provenance envelopes. This profile does not define cryptographic algorithms and does not claim regulatory compliance.

## Non-goals

This profile does not provide:

- an agent runtime
- a marketplace
- an identity provider
- model hosting
- prompt filtering
- regulatory certification
- a commercial control plane
- full MCP proxy behavior
