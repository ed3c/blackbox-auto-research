# OpenShell Integration

Issue: #19

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
reference_surface: provider adapter and policy mapping
completion_requires: real OpenShell execution
```

## Agent task

Use the existing provider-neutral RunManifest and ResourcePolicy to execute a disposable candidate in a real OpenShell environment. Prove both allowed and denied behavior. Never fall back to host execution when OpenShell is unavailable.

## Required probes

- denied network destination;
- allowed network destination;
- read-only and writable filesystem boundaries;
- allowed and denied credential names;
- evaluator mutation/exfiltration attempt;
- budget abort;
- teardown/reset state-leak probe.

## Required evidence

Follow `../EVIDENCE_CONTRACT.md`, plus OpenShell version/runtime identity and policy-enforcement events.

## Done

#19 can close only after a real session produces replayable evidence and an independent verifier confirms the expected final state and denied operations.
