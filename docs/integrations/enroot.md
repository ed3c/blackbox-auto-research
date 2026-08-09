# Enroot GPU/HPC Integration

Issue: #21

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
trust_class: filesystem-separated / HPC runtime
```

## Agent task

Run the candidate on a real Enroot-capable GPU/HPC worker and measure the actual boundary. Do not describe Enroot as equivalent to a stronger policy-isolated sandbox unless evidence proves that property in the deployment.

## Required probes

- container launch and cleanup;
- mount/filesystem separation;
- evaluator artifact outside candidate-writable mounts;
- GPU/runtime fingerprint;
- concurrent resource contention;
- process crash/cleanup;
- unsupported isolation guarantees documented.

## Done

#21 closes when the measured trust boundary and failure behavior are backed by live worker evidence.
