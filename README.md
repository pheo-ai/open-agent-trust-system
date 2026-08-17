# OATS: Open Agent Trust System

A vendor-neutral profile and reference runtime for agent authority, lifecycle evidence, and release receipts.

## The Problem

AI agents and skills are becoming portable executable assets. Enterprises need a common way to answer the questions that matter before an agent acts:

- What is this agent or skill allowed to do?
- Who granted that authority?
- Did this exact action require review?
- What was approved, blocked, or demoted?
- What receipt proves the decision?
- Can another system verify the evidence without receiving private data?

OATS defines the minimum portable objects for that boundary: authority policy, lifecycle state, action receipts, and autonomy transitions.

```text
portable agent or skill
  -> SkillManifest
  -> AutonomyPolicy
  -> governed action
  -> ActionReceipt
  -> AutonomyTransition / LifecycleAttestation
```

Commercial runtimes may implement this profile; this reference package is vendor-neutral.

## What This Repo Contains

```text
schemas/             JSON Schema drafts
validator/           dependency-free profile and policy checks
reference_runtime/   OATS Reference Runtime: tiny policy gate, receipt emitter, transition demo
examples/            coding, invoice, literature, and marketing policies
tests/               executable contract and threat-model tests
docs/                OpenSharing, MCP, problem, and threat-model notes
```

## Quick Start

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
receipt signature: HMAC-SHA256 demo-review-key
```

## Core Objects

- `SkillManifest`: identifies a versioned agent or skill artifact and declared action classes.
- `AutonomyPolicy`: maps action classes to authority states and oversight requirements.
- `LifecycleAttestation`: records publisher, provenance, status, and lifecycle events.
- `ActionReceipt`: records a governed action request, decision, policy, and digest.
- `AutonomyTransition`: records evidence-backed promotion, demotion, rollback, or revocation.

## Lifecycle States

```text
observe -> supervised -> act_with_approval -> bounded_autonomous
    ^          ^                 ^                    |
    +----------+-----------------+--------------------+
                 demotion / rollback
```

`revoked` is terminal until a new approval process explicitly restores use. Authority is applied per action class, not only per agent or skill.

## Action Receipt Semantics

An `ActionReceipt` records the governed decision for a single action request. It binds together artifact identity, action class, exact request digest, policy digest, autonomy state, decision, timestamp, and receipt digest.

The request digest enables exact-payload approval. If the payload changes, the previous approval no longer applies.

## Boundaries

OATS does not define a marketplace, agent runtime, model provider, identity provider, storage service, compliance certification, or UI. Portable documents should contain identifiers, references, digests, and minimum necessary decision metadata. Raw prompts, source code, research papers, invoices, emails, and personal data should remain in customer-controlled stores.

OpenSharing can handle exchange. MCP can handle tool connectivity. OATS defines authority, receipts, and lifecycle evidence.

## Status

Draft reference implementation for private community review. This is not currently a Linux Foundation project and does not imply Linux Foundation endorsement.
