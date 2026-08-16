# MCP Mapping

This profile can be used at MCP tool-call boundaries.

## Mapping

- MCP client/server/tool identity -> `skill_ref` and action context
- MCP tool name -> `action.class`
- MCP tool arguments -> canonical request object
- SHA-256 of canonical request -> `action.request_digest`
- Policy decision -> `decision.status`
- Human approval -> `decision.method = human` and `decision.approver_id`
- Receipt hash -> `integrity.receipt_digest`

## Exact-payload approval

A human approval applies only to the canonical request payload that produced the recorded digest. If the tool arguments change, the approval must be requested again.

## Non-goal

This repository does not implement a full MCP proxy. It defines the portable receipt and lifecycle objects an MCP-aware runtime can emit.
