# Production Promotion

Issue: #28

```yaml
current_maturity: L2_SANDBOX
target_maturity: L4_PRODUCTION
required_order: [offline, shadow, canary, production]
```

## Agent task

Connect the existing promotion state machine to a disposable real deployment/control plane through an adapter.

## Required probes

- offline gate consumes stored evidence;
- shadow receives mirrored/non-authoritative traffic;
- canary cohort/traffic percentage is explicit;
- live guardrail/SLO failure blocks promotion;
- evaluator/environment drift blocks promotion;
- required stage cannot be skipped;
- irreversible production action requires human approval;
- rollback changes actual deployment state and emits a receipt.

## Done

#28 closes when staged promotion and rollback are demonstrated against a real disposable deployment backend with evidence stored outside the deployment worker.
