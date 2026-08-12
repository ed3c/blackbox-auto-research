# OpenShell Integration

Issue: #19

```yaml
current_maturity: L3_LIVE
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

The replayable live-evidence harness covers this contract:

```bash
python3 scripts/produce_live_openshell_evidence.py --help
python3 scripts/verify_live_openshell_evidence.py --help
```

It records real network, filesystem, credential-name isolation, evaluator-isolation,
budget and teardown probes in a content-addressed bundle. Credential validation uses
a one-run synthetic canary: the candidate receives only an opaque OpenShell placeholder,
the real canary is committed by digest but never persisted, and an unattached credential
name remains absent. This proves provider attachment and candidate-side credential
isolation; it does not claim upstream placeholder substitution against an external HTTPS
service.

## Done

#19 reached `L3 LIVE` with the v5 bundle produced on OpenShell 0.0.59 and independently
verified outside the candidate process. This does not imply `L4 PRODUCTION`: external
object storage, managed signing, multi-host recovery and retention remain issue #25.
