# Threat Model

This draft profile focuses on evidence for agent skill authority and lifecycle decisions.

## In scope

- over-broad skill authority
- unclear human authorization
- unreviewed high-impact actions
- changed payload after approval
- missing action audit trail
- unsafe autonomy promotion
- fail-open behavior after critical errors

## Out of scope

- model jailbreak prevention
- prompt injection detection
- endpoint DLP
- identity-provider implementation
- sandbox escape prevention
- legal compliance certification
- an adversary writing commands to evade a resolver whose grammar they know

## Assumed uncompromised

A gate invoked as a hook by an agent that can run shell commands is not
tamper-proof against that agent, and this profile does not pretend otherwise.
The following are assumed intact, and none is defended against the governed
agent itself:

- the hook registration in the agent's configuration
- the binary the hook invokes
- the ledger store

Integrity is provided over the *record*, not over enforcement. Receipts carry a
digest over their own contents, a link to the previous receipt's digest, and a
signature under an operator-held key, so a ledger edited after the fact does not
verify. That detects tampering with history. It does not stop an agent from
disabling the control prospectively, or from invoking a tool by a path the hook
does not cover. Tamper-resistance in the reference-monitor sense needs the
monitor to sit outside the agent's reach, which a locally installed hook does
not.

## Design responses

- Per-action-class autonomy avoids blanket skill authority.
- Exact-payload request digests bind approvals to the approved payload.
- Receipts link skill, policy, action, decision, timestamp, and digest.
- Promotion requires authorization.
- Demotion is fail-safe and can be automatic.
- Portable documents avoid raw customer data by default.
