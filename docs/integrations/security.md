# Adversarial Security Validation

Issue: #26

```yaml
current_maturity: L2_SANDBOX
target_maturity: L4_PRODUCTION
scope: owned isolated test environments only
```

## Agent task

Attack this runtime's own trust assumptions and verify every anomaly fails closed or enters quarantine.

## Required probes

- evaluator mutation;
- hidden-case discovery/inference;
- path traversal/symlink escape;
- denied network egress/covert channel;
- credential enumeration/access;
- evidence/artifact poisoning;
- prompt/tool injection in harness-facing inputs;
- replay/provenance tampering;
- resource exhaustion and cleanup.

## Evidence

Each probe needs expected policy, observed behavior, evidence digest, decision and cleanup result. Never run these probes against third-party systems without authorization.

## Done

#26 closes when the suite runs automatically against the production candidate runtime class and all seeded violations are detected and contained.
