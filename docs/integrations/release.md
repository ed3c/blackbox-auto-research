# Release Engineering

Issue: #29

```yaml
current_maturity: L1_REFERENCE
target_maturity: L4_PRODUCTION
```

## Agent task

Turn repository-local execution into a pinned, installable and auditable release.

## Required outputs

- package metadata and supported Python policy;
- CLI for validate/run/replay/inspect;
- reproducible dependency lock strategy;
- SBOM;
- dependency/security scanning;
- signed artifact/provenance mechanism;
- package/OCI distribution decision;
- provider/harness/platform compatibility matrix;
- release notes and migration policy;
- clean-room install/run/uninstall smoke test.

## Release gate

Do not call the project v1.0 production-ready while live integrations and production controls required by `../INTEGRATION_ROADMAP.md` remain unproven. A release candidate may document unsupported integrations explicitly.
