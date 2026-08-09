# Evidence Contract

## Principle

Completion is based on externally inspectable evidence, not an Agent's narration or a candidate-reported score.

## Required run envelope

For an integration validation, capture when applicable:

- task/scenario identifier and digest;
- candidate identifier/digest and parent lineage;
- RunManifest;
- environment/provider/device image or capability digest;
- harness/model/runtime identity;
- evaluator digest and qualification status;
- policy digest;
- seed/trial identity;
- start/end timestamps and budgets;
- trajectory/actions/observations;
- externally visible side effects;
- final-state digest;
- evidence artifact digests and locators;
- independent evaluation;
- decision and reason;
- teardown/reset/rollback receipt.

## Evidence classes

### Outcome evidence

Proves the requested state exists: database row, file digest, API state, UI/app state, service health, deployment state, etc.

### Policy evidence

Proves denied and allowed behavior at the runtime boundary: network, filesystem, credentials, evaluator access, destructive actions.

### Provenance evidence

Binds task/candidate/environment/harness/evaluator/policy identities to the run and detects tampering or drift.

### Reliability evidence

Repeated trials, failure injection, retry behavior, reset isolation and cleanup.

### Operational evidence

Latency, cost, resource usage, queue/device health, alerts, SLOs and rollback/recovery.

## Evidence quality hierarchy

Prefer, in order:

1. programmatic external-state verifier;
2. invariant/property/differential/metamorphic verifier;
3. signed/tamper-evident runtime or provider event;
4. structured logs/traces from an independent control plane;
5. model-based semantic judge;
6. human review.

A model judge should not be the only proof when a deterministic state verifier is possible.

## Forbidden completion shortcuts

The following do not independently prove integration completion:

- adapter class exists;
- generated command looks correct;
- mock/fake provider passes;
- candidate says it succeeded;
- screenshot without state provenance when stronger state evidence exists;
- a single stochastic trial;
- logs written by the candidate itself;
- unpinned evaluator or environment;
- evidence only present on the worker that produced it for a production claim.

## Storage

Reference/local evidence may use the repository's content-addressed store. L4 claims require the production evidence-lake requirements tracked in #25.
