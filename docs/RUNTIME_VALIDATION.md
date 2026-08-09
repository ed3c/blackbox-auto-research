# Runtime Validation Contract

## Core distinction

```text
CODE EXISTS
    !=
REFERENCE TESTED
    !=
SANDBOX VALIDATED
    !=
LIVE VALIDATED
    !=
PRODUCTION VALIDATED
```

## Maturity gates

### L0 CONTRACT

Required:
- versioned interface/schema;
- invalid input fails closed;
- provider/domain types do not leak into core contracts.

### L1 REFERENCE

Required:
- deterministic reference implementation;
- positive and planted-negative tests;
- reset/state-isolation test where state exists;
- `bash verify.sh` passes.

### L2 SANDBOX

Required:
- disposable isolated runtime;
- pinned environment identity;
- actual action execution, not generated-command inspection;
- trajectory and final-state evidence;
- independent verifier result;
- teardown/reset proof;
- replay or re-verification from stored evidence.

### L3 LIVE

Required:
- intended real provider/device/service;
- version/capability fingerprint;
- real policy enforcement or real outcome verification;
- failure injection;
- repeated trials when stochastic;
- no private credentials/identifiers committed;
- evidence is retrievable outside the candidate process;
- limitations and unsupported guarantees are explicit.

### L4 PRODUCTION

Required:
- least-privilege access and secrets handling;
- adversarial security suite;
- durable signed/tamper-evident evidence;
- metrics/traces/cost accounting and SLOs;
- shadow/canary/approval/rollback where changes reach users;
- backup/recovery and drift detection;
- release provenance and compatibility policy.

## Completion rule

An issue can advance only to the highest level for which all required evidence exists. Partial evidence should update the issue checklist but must not inflate the maturity label.

## PR contract

Every integration PR must include:

- issue and integration contract;
- maturity before / maturity after;
- hypothesis being tested;
- exact environment/provider/device version;
- validation command(s);
- evidence digests/locations;
- independent verifier result;
- failure injection performed;
- known limitations;
- rollback/cleanup result where applicable.

## Blockers

If live provider access, hardware, credentials, signing material, or deployment infrastructure is unavailable, record a blocker. Do not replace the missing proof with a mock and do not close the issue.
