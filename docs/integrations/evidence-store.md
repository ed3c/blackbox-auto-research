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
  --floci-repo "$FLOCI_REPO" \
  --artifacts-dir evidence/floci/floci-sandbox-001 \
  --receipt evidence/floci/floci-sandbox-001/runner-receipt.json \
  --run-id floci-sandbox-001
```

This is an `L2 SANDBOX` compatibility experiment only. Its receipt is hard-coded
to `provider_kind=floci-emulator`, `maturity=L2 SANDBOX`, and
`production_claim_allowed=false`. A wrong-secret planted negative that is accepted
produces a `quarantine` receipt and a non-zero exit code. The artifact directory
is reserved with exclusive creation and preserves the input payload, IAM policy,
producer manifest and fresh-process verifier receipt. The final runner receipt is
written last as the completion marker; failures remove the runner-owned directory.
The receipt records child locators, SHA-256 digests, sizes and a reproduction
command whose `FLOCI_REPO` contract is pinned to the source commit and whose
`NEW_ARTIFACTS_DIR` must not already exist.

Run `floci-sandbox-20260812-10` against clean Floci commit
`c21337c3b185ab0c436cdfbc2bede70dadc8330c` and image
`sha256:44a4120fc38df1a94da34dbdcf3705f9c877b33fd9f224a986d3f973bf9d85fd`
published a replayable quarantine bundle under
`evidence/floci/floci-sandbox-20260812-10/`. It verified S3 content-addressed
round-trip, WAL restart, fresh-process retrieval and IAM delete denial. The
wrong-secret Authorization-header `HeadObject` succeeded, so Floci is not
qualified and #25 does not advance. The enforcement gap remains open as #56.
Run `floci-sandbox-20260812-04` is retained only as a superseded pre-probe-binding
receipt; it is not a canonical replay target.
Run `floci-sandbox-20260812-05` is likewise superseded because it predates exact
sandbox identity, credential-variant and IAM-policy semantic binding.
Run `floci-sandbox-20260812-07` is superseded because phase targets were not yet
attested by both the producer manifest and fresh verifier receipt.
Run `floci-sandbox-20260812-08` is superseded because the worker did not yet
cross-check its actual endpoint and CA bytes against the attested phase target.
Run `floci-sandbox-20260812-09` is superseded because its CA attestation still
re-read a provider-writable path instead of using a runner-owned immutable snapshot.

The exact runner invocation is recorded as `reproduction_command` in the final
receipt. `FLOCI_REPO` must be a clean checkout at the pinned commit and
`NEW_ARTIFACTS_DIR` must not exist. Replay the stored result without network:

```bash
python3 scripts/verify_floci_sandbox_bundle.py \
  --receipt evidence/floci/floci-sandbox-20260812-10/runner-receipt.json
```

Artifact SHA-256 digests:

- IAM policy: `7d5d46fefc0762f3cdea35fe4d218a21cbcfee46b50a9a4bc1820fad77b95c70`;
- input payload: `da3f4ffac5da5a30f9d42807ddb5fd76123d0111c4269d5d6257a9190d349030`;
- producer manifest: `b13f3006788aeec469a855484d1281515d9a967971893d325b90ae272f4420bb`;
- fresh-process verifier receipt: `f9d849c809f0f5dcbcfc6bd9871c687b51c7da7512dfeeb58919de4f4c92b4b1`;
- final runner receipt: `3367fc734b415618ec11bfa39ead7324696b016949a9eefe9d43eba73a761bd0`.

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
