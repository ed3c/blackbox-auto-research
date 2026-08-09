# Production Evidence Lake

Issue: #25

```yaml
current_maturity: L2_SANDBOX
target_maturity: L4_PRODUCTION
```

## Agent task

Replace worker-local filesystem durability as the production boundary with provider-neutral blob + metadata interfaces and at least one production-grade deployment implementation.

## Required properties

- immutable content-addressed blobs;
- indexed run/candidate/evaluator/environment metadata;
- concurrency-safe append/event semantics;
- signing/KMS or equivalent provenance;
- encryption and least privilege;
- retention/deletion policy;
- failed/discarded/quarantined queryability;
- backup/restore and corruption recovery;
- evaluator/environment drift queries.

## Done

A fresh verifier process with no access to the original worker filesystem can retrieve evidence, validate provenance and reproduce the recorded decision.
