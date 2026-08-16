# OpenSharing Mapping

This profile is intended to compose with OpenSharing `AgentSkill` assets.

## Mapping

- OpenSharing `AgentSkill` asset -> `SkillManifest`
- Asset version/digest -> `manifest_digest`
- Shared skill capabilities -> `capabilities.action_classes`
- Provider/publisher metadata -> `publisher`
- Runtime authority metadata -> `AutonomyPolicy`
- Release provenance -> `LifecycleAttestation`
- Governed action evidence -> `ActionReceipt`
- Promotion, demotion, revocation -> `AutonomyTransition`

## Boundary

OpenSharing can define how an AI asset is exchanged. This profile defines portable trust and lifecycle evidence around that asset. It does not replace OpenSharing transport, discovery, credential vending, or access APIs.
