# Distributed Workers and Device Scheduling

Issue: #23

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
```

## Agent task

Turn reference lease/RNG/search isolation into a real concurrent scheduler/worker experiment.

## Required probes

- exclusive lease under contention;
- heartbeat and lease expiry;
- worker crash + idempotent retry;
- duplicate execution suppression;
- global and per-candidate budget accounting;
- stable per-candidate randomness independent of worker assignment;
- controller restart/checkpoint recovery;
- cross-worker/device state-leak canary.

## Done

#23 closes only after concurrency is exercised across at least two independent workers/devices and failure recovery evidence is retained.
