# OATS: Open Agent Trust System

A profile for agent authority, lifecycle evidence, and release receipts.

## The Problem

Agents have started doing real work on real systems. They install packages,
edit code, call APIs, move money, and click through live sites on a user's
behalf.

Most of what goes wrong there does not look like an attack. Nobody was
hijacked and nothing was injected. Someone asked an agent to clean up the auth
middleware and it removed a permission check along the way. Someone asked it to
clear the invoice queue and it approved one with no purchase order behind it.
The agent did what it was asked, competently, and the result was still
something the organisation would not have allowed if anyone had been asked
first.

Existing controls are built to find an attacker, and this is not that. The
question is not *was this malicious*. It is *was this permitted*, and that has
a different answer at every organisation. A two-person startup and a bank do
not owe each other the same answer about who may push to production or read a
credentials file. That answer is not a property of the artifact, so it cannot
be settled by inspecting one.

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
spec/                the 33 consequence classes: key, severity rank, graduation
validator/           dependency-free profile and policy checks
reference_runtime/   OATS Reference Runtime: policy gate, receipt emitter, transition demo
examples/            coding, invoice, literature, and marketing policies
tests/               executable contract tests
docs/                OpenSharing, MCP, problem, and threat-model notes
paper/               the measurement study behind the profile
research/            reproduction script and the governance benchmark
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

## When Authority Should Change

The states above describe where authority can go. They do not say what
justifies moving. A profile that leaves that open permits an implementation to
reach `bounded_autonomous` after a single clean run, which is conformant and
indefensible.

Two failure modes bound the answer. Hold every consequential action forever and
operators disable the control, which is the documented history of alerting
products; a control that is off protects nobody. Promote on a short clean
streak and authority is granted on evidence that does not support it. Ten clean
approvals feels sufficient. By the rule of three, observing zero failures in
ten trials bounds the true failure rate at 25.9% with 95% confidence.

The transition threshold is therefore derived rather than chosen. For a class
whose tolerable failure rate is `e`, the clean-run count required at confidence
`1 - d` is:

```text
N = ceil( ln(d) / ln(1 - e) )
```

At 95% confidence:

| Action class | Tolerable failure rate | Clean runs required |
|---|---|---|
| Docs, tests, reads | 10% | 29 |
| Shell execution | 5% | 59 |
| Business logic, dependencies | 2% | 149 |
| Deploy, IAM, CI configuration | 0.5% | 598 |
| Remote execution, credentials, secrets, destructive | 0% | never |

The tolerable failure rate is the operator's parameter, not the profile's. The
last row is the profile's: some action classes admit no finite `N`, because no
length of clean record makes an unrecoverable action recoverable. An
implementation that promotes such a class is not conformant.

This is what `ActionReceipt` is for beyond audit. Each recorded decision is one
unit of evidence in one lane, so the record an operator accumulates by using a
governed system is the same record that eventually justifies a transition.

## Why The Boundary Needs A Profile

Registries already scan skills before publication. That check reads the
artifact once, before anything runs, and it cannot encode what a given
operator permits. The two are different questions and they have different
answers on the same file.

Measured against the largest public agent-skill registry, using the scan
results that registry publishes itself:

- **705 skills**, from 135 distinct publishers, are marked clean by every
  scanner in that registry's pipeline while instructing an agent to fetch
  code from the network and execute it. Clean is the correct verdict. It is
  not the same as permitted. Read that number with its distribution: one
  publisher accounts for 506 of the 705, and 117 of the 135 publishers
  contribute exactly one skill each. A hand audit of 100 puts the detector's
  precision at 92% (95% CI [85%, 97%]).
- Of **93 commands** a live agent issued while following real skill
  documentation, **3** appeared verbatim in that documentation, and **36.6%**
  had a consequence class that appeared in no code block of it at all. The
  scanned artifact is not the executed artifact.
- All four signals return clean on **44.2%** of skills. That is agreement on a
  verdict, not agreement on what they looked at: the registry's own study
  reports that any two of the underlying scanners overlap on at most 10.4% of
  their combined positives.

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

This defaults to the whole corpus, all four splits, 66,192 skills, which is
what the paper reports. It downloads about 1.6 GB and runs for several hours.
It prints the count with a per-class breakdown and the per-publisher
distribution, and writes the skills themselves to `clawhub_reproduction.csv`.

Pass `--split eval_holdout` for a 3,339-skill smoke test that finishes in
minutes; the numbers will not match the paper and the script says so when you
do. No single split reproduces the paper: `train` alone is 46,325 skills.

## The benchmark

An implementation that resolves `curl … | bash` may still miss
`curl -o s URL; chmod +x s; ./s`, which does the same thing. Until the field can
state how much of an action's equivalence class a gate covers, no two gates can be
compared and no implementation can show it is improving.

`research/evasion_bench.py` is 64 semantics-preserving rewrites across nine
techniques. Each rewrites a base action whose consequence class is not in dispute, so
a miss needs no judgement call. Run it against any implementation:

```bash
pip install pheo-oats requests
oats start --no-browser &
python research/evasion_bench.py
```

The reference implementation resolves **52%** macro-averaged over the eight
rewriting techniques, which is the headline because per-technique case counts are
an artifact of how many variants each generator emits. Micro-averaged over cases it
is 75%, or 77% counting the identity controls. A case counts as resolved if it
lands at or above the base action's severity, since over-classifying still protects
the operator.

The per-technique breakdown is the useful part: wrapping and chaining resolve
completely, staged fetch-then-execute resolves at zero, because no single command in
it is remote execution. Adding a
technique is a function returning command strings, and new techniques are more
valuable than tuning against the existing ones.

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

