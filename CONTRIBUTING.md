# Contributing

This is a draft interoperability contribution intended for private review before any public OpenSharing discussion or pull request.

## Principles

- Keep the profile vendor-neutral and useful without Pheo.
- Prefer existing OpenSharing, MCP, DSSE, in-toto, SLSA, and Sigstore terminology.
- Never require raw customer data in portable documents.
- Treat signatures and digests as evidence, not as proof of legal compliance.
- Promotion must be explicitly authorized; demotion must fail safe.
- Add a test fixture for every schema or transition rule.

## Developer Certificate of Origin

Contributions should include a DCO sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Use:

```bash
git commit -s
```

## Before sharing upstream

1. Review the schemas with at least one OpenSharing maintainer or ecosystem reviewer.
2. Confirm naming and extension points fit the project.
3. Replace illustrative thresholds with documented policy semantics.
4. Add conformance fixtures for every schema object.
5. Run `make test`, `make demo`, and `make validate`.

This repository is not yet an LF project and should not imply endorsement.
