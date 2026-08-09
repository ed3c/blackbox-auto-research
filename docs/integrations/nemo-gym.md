# NeMo Gym Integration

Issue: #20

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
core_rule: keep NeMo Gym types behind the compatibility bridge
```

## Agent task

Pin an installed NeMo Gym version, execute one real environment + harness + verifier rollout, import the rollout into the repository Trajectory contract, and prove stored-rollout re-verification without rerunning inference.

## Required probes

- version/API mismatch must fail explicitly;
- task/manifest mapping;
- real rollout execution;
- trajectory round trip;
- evaluator digest drift;
- stored rollout re-verification;
- SKILL.md candidate digest preservation.

## Evidence

Record dependency lock/version, raw rollout locator/digest, imported trajectory digest, evaluator digest, original evaluation and replay evaluation.

## Done

#20 closes only after the bridge is proven against a real pinned NeMo Gym installation. Unit-level schema mapping alone remains L1.
