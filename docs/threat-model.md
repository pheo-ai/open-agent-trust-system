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

## Design responses

- Per-action-class autonomy avoids blanket skill authority.
- Exact-payload request digests bind approvals to the approved payload.
- Receipts link skill, policy, action, decision, timestamp, and digest.
- Promotion requires authorization.
- Demotion is fail-safe and can be automatic.
- Portable documents avoid raw customer data by default.
