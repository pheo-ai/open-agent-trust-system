# OpenSharing Skill Trust & Lifecycle Profile

A small, vendor-neutral profile for AI skill authority, lifecycle state, and action receipts.

## The problem in 60 seconds

AI skills are becoming portable executable assets. OpenSharing can exchange those assets. MCP can connect agents to tools. But enterprises still need a portable way to answer the questions that matter before a skill acts:

- What is this skill allowed to do?
- Who authorized that authority?
- Did this exact action require review?
- What payload was approved or blocked?
- When should autonomy be promoted, demoted, or revoked?
- Can another system verify the evidence without receiving raw customer data?

This profile defines the minimum vocabulary and evidence format for that boundary.

```text
OpenSharing AgentSkill
  -> SkillManifest
  -> AutonomyPolicy
  -> governed action
  -> ActionReceipt
  -> AutonomyTransition / LifecycleAttestation
```

Commercial runtimes may implement this profile; this reference package is vendor-neutral.

## What this repo contains

```text
schemas/             JSON Schema draft 2020-12 documents
validator/           dependency-free profile and policy checks
reference_runtime/   tiny policy gate, receipt emitter, transition demo
examples/            coding, invoice, literature, and marketing policies
tests/               executable contract tests
```

## Quick start

Requires Python 3.9+ and no third-party dependencies.

```bash
make test
make demo
make validate
```

Expected demo behavior:

```text
read_files: allowed
propose_patch: pending_review -> approved
apply_patch: pending_review -> approved
commit: pending_review -> approved
deploy: blocked
demotion emitted
receipt digest created
```

## Core objects

- `SkillManifest`: identifies a versioned skill artifact and declared action classes.
- `AutonomyPolicy`: maps action classes to authority states and oversight requirements.
- `LifecycleAttestation`: records publisher, provenance, status, and lifecycle events.
- `ActionReceipt`: records a governed action request, decision, policy, and digest.
- `AutonomyTransition`: records evidence-backed promotion, demotion, rollback, or revocation.

## Lifecycle states

```text
observe -> supervised -> act_with_approval -> bounded_autonomous
    ^          ^                 ^                    |
    +----------+-----------------+--------------------+
                 demotion / rollback
```

`revoked` is terminal until a new approval process explicitly restores use. Autonomy is applied per action class, not only per skill.

## Design boundaries

This profile does not define a marketplace, agent runtime, model provider, identity provider, storage service, or compliance certification. Portable documents should contain identifiers, references, digests, and minimum necessary decision metadata. Raw prompts, source code, research papers, invoices, and personal data should remain in customer-controlled stores.

## Status

Draft reference implementation for private community review. This is not currently a Linux Foundation project and does not imply Linux Foundation endorsement.
