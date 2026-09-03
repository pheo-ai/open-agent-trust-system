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
paper/               the measurement study behind the profile
research/            script to reproduce that study
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

## Why The Boundary Needs A Profile

Registries already scan skills before publication. That check reads the
artifact once, before anything runs, and it cannot encode what a given
operator permits. The two are different questions and they have different
answers on the same file.

Measured against the largest public agent-skill registry, using the scan
results that registry publishes itself:

- **822 skills**, from 187 unrelated publishers, are marked clean by every
  scanner in that registry's pipeline while instructing an agent to fetch
  code from the network and execute it. Clean is the correct verdict. It is
  not the same as permitted.
- Of **93 commands** a live agent issued while following real skill
  documentation, **3** appeared in that documentation. The scanned artifact
  is not the executed artifact.
- Four scanners reading the same files agree on **45%** of them.

Method, limits, and what the numbers do not show:
[Scan the Skill, Govern the Action](paper/scan-the-skill-govern-the-action.pdf).

## Reproducing The Evidence

The registry's scan results are public and MIT licensed, so the starting
point needs nothing from us. In the SQL console on
[OpenClaw/clawhub-security-signals](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals):

```sql
SELECT COUNT(*) AS total,
       SUM(CASE WHEN clawscan_verdict='clean' AND static_status='clean'
                 AND virustotal_status='clean' AND skillspector_status='clean'
            THEN 1 ELSE 0 END) AS all_four_agree_clean
FROM eval_holdout;
```

3,339 skills, 1,501 that all four scanners agree are clean.

Counting skills that are clean *and* instruct an unearned action requires
something that classifies actions. Any OATS implementation will do; the
script below uses one:

```bash
pip install pheo-oats pandas pyarrow requests
oats start --no-browser &
python research/reproduce_clawhub.py
```

On the 3,339-skill holdout split this takes a few minutes and prints the
count with a per-class breakdown, writing the skills themselves to
`clawhub_reproduction.csv`. Pass `--split train` for the full 66,192-skill
corpus, which is where the 822 figure comes from.

## Implementations

The profile is designed to be useful without any commercial runtime. The
`reference_runtime/` in this repository is dependency-free and implements the
policy gate, receipt emission, and transition demo directly from the schemas.

Known implementations:

| | |
|---|---|
| `reference_runtime/` | This repository. Dependency-free, for conformance and reading. |
| [Pheo OATS](https://pypi.org/project/pheo-oats/) | Production gateway. `pip install pheo-oats`. Proprietary. |

Additional implementations are welcome. Conformance means emitting the objects
in `schemas/` and passing `validator/`.

