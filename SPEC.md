# Open Agent Trust Specification Overview

## Scope

Open Agent Trust adds portable authority, lifecycle, and receipt metadata to agent and skill artifacts. It is intended to compose with OpenSharing `AgentSkill` assets, MCP tool boundaries, and provenance systems such as DSSE, in-toto, SLSA, and Sigstore.

The profile standardizes evidence for authority decisions. It does not standardize agent reasoning, model behavior, marketplace operations, or enterprise enforcement UX.

## Object Model

- `SkillManifest` identifies an agent or skill artifact, publisher, version, digest, and declared action classes.
- `AutonomyPolicy` defines the allowed autonomy state and oversight rule for each action class.
- `LifecycleAttestation` records provenance, publication status, and lifecycle events for an artifact release.
- `ActionReceipt` records a governed action request, its policy context, decision, payload digest, and receipt digest.
- `AutonomyTransition` records evidence-backed state changes for one action class.

## Lifecycle States

```text
observe -> supervised -> act_with_approval -> bounded_autonomous
    ^          ^                 ^                    |
    +----------+-----------------+--------------------+
                 demotion / rollback
```

- `observe`: the artifact may be inspected but cannot act.
- `supervised`: every output or action requires human review before release.
- `act_with_approval`: the artifact may prepare actions but execution requires exact-payload approval.
- `bounded_autonomous`: the artifact may execute within policy limits and produces receipts.
- `revoked`: the artifact cannot act until explicitly restored by a new approval process.

Implementations must apply authority per action class. An agent may be autonomous for reversible reads while remaining supervised for writes, patches, payments, or deployments.

## Action Receipt Semantics

An `ActionReceipt` records the governed decision for a single action request. It must bind together:

- artifact identity and manifest digest
- action class and request digest
- policy identity and policy digest
- current autonomy state
- decision status, method, reason, and optional approver
- timestamp and receipt digest

The request digest enables exact-payload approval. If the payload changes, the previous approval no longer applies.

## Transition Semantics

An `AutonomyTransition` records a promotion, demotion, rollback, or revocation. Promotion requires explicit authorization. Demotion should be fail-safe and may be triggered automatically by policy violation, critical failure, drift, or elevated correction rate.

## Security And Privacy

Portable profile documents should contain references and digests by default. They should not require raw customer data, private prompts, source code, research text, invoices, emails, or personal data.

Implementations may wrap documents in established signing and provenance envelopes. This profile does not define cryptographic algorithms and does not claim regulatory compliance.

## Non-Goals

This profile does not provide:

- an agent runtime
- a marketplace
- an identity provider
- model hosting
- prompt filtering
- regulatory certification
- a commercial control plane
- full MCP proxy behavior
