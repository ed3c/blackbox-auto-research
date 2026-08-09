# Observability and SRE

Issue: #27

```yaml
current_maturity: L1_REFERENCE
target_maturity: L4_PRODUCTION
```

## Agent task

Make control-plane, runtime, verifier, evidence and promotion behavior diagnosable without coupling the core to one telemetry vendor.

## Required signals

- trace/run/experiment correlation IDs;
- structured lifecycle events;
- success/failure/quarantine/retry/drift metrics;
- latency and resource usage;
- token/API/compute/device cost;
- queue/worker/device lease health;
- sandbox failure taxonomy;
- evidence durability and evaluation-availability SLOs;
- production drift alert.

## Done

An operator can answer: what failed, whether the cause was candidate or infrastructure, what it cost, which evidence supports the decision, and whether recovery/rollback succeeded.
