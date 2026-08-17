# OATS: Open Agent Trust System

A profile for agent authority, lifecycle evidence, and release receipts.

## The Problem

AI skills and agents are becoming portable executable assets. Developers need a common way to answer the questions that matter before an agent acts:

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

## What This Repo Contains

```text
schemas/             JSON Schema draft 
validator/           dependency-free profile and policy checks
reference_runtime/   OATS Reference Runtime: policy gate, receipt emitter, transition demo
examples/            coding, invoice, literature, and marketing policies
tests/               executable contract tests
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

