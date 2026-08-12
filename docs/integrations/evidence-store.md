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

## Floci sandbox harness

The repository includes an AWS-compatible, path-style `S3CompatibleBlobStore` and
an opt-in Floci experiment runner. The runner builds a caller-supplied local Floci
clone, pins the resulting image ID, enables WAL/TLS/IAM and the SigV4 configuration
flag, writes through a restricted IAM principal, restarts the emulator, then reads
the artifact from a fresh verifier process.

```bash
python3 scripts/run_floci_evidence_store_sandbox.py \
  --floci-repo /path/to/floci \
  --receipt /tmp/floci-evidence-store-receipt.json \
  --run-id floci-sandbox-001
```

This is an `L2 SANDBOX` compatibility experiment only. Its receipt is hard-coded
to `provider_kind=floci-emulator`, `maturity=L2 SANDBOX`, and
`production_claim_allowed=false`. A wrong-secret planted negative that is accepted
produces a `quarantine` receipt and a non-zero exit code.

At Floci commit `c21337c3b185ab0c436cdfbc2bede70dadc8330c`, a diagnostic run
reached S3 write/read, WAL restart and fresh-process retrieval before its combined
security probe failed. The wrong-secret path was identified as permissive by source
inspection, but the three-attempt stop-loss prevented a final post-fix receipt.
Those observations are not a completed qualification or maturity advance.

Source inspection also found
that `FLOCI_AUTH_VALIDATE_SIGNATURES` is consumed for pre-signed URL handling but
does not establish a regular Authorization-header SigV4 validation filter. The
configuration flag must therefore never be reported as proof of request-signature
enforcement. No Floci result checks any production requirement below or changes
the current maturity.

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
