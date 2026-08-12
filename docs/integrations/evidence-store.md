# Production Evidence Lake

Issue: #25

```yaml
current_maturity: L2_PLUS
target_maturity: L4_PRODUCTION
```

## Proven in repository/CI

- provider-neutral `BlobStore` and `ProvenanceSigner` protocols;
- immutable content-addressed directory blob backend;
- SQLite metadata/index backend with WAL and `BEGIN IMMEDIATE` serialized append;
- signed per-run event chains;
- fresh-process reopen and provenance verification;
- candidate/evaluator/environment lookup;
- tamper and wrong-signing-key rejection.

These are production-shaped reference primitives. `HMACSigner` is explicitly a test/reference signer and does not substitute for KMS/HSM provenance.

## Remaining production requirements

- [ ] external object/blob store implementation;
- [ ] production metadata/index service suitable for multi-host writers;
- [ ] KMS/HSM or equivalent managed signing;
- [ ] encryption and least-privilege IAM validation;
- [ ] retention/deletion policy implementation;
- [ ] failed/discarded/quarantined operational queries;
- [ ] backup/restore and corruption recovery against the external stores;
- [ ] multi-host concurrency/recovery test;
- [ ] fresh verifier on another worker retrieves evidence and reproduces the decision.

## Done

#25 closes only when a fresh verifier process on an independent worker can retrieve external evidence, validate managed provenance and reproduce the recorded decision. SQLite/directory tests alone must not close the issue.
