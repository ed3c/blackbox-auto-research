# Floci evidence-lake assessment

Assessment date: 2026-08-12

Evaluated source: `floci-io/floci` commit
[`c21337c3b185ab0c436cdfbc2bede70dadc8330c`](https://github.com/floci-io/floci/tree/c21337c3b185ab0c436cdfbc2bede70dadc8330c).

## Decision

Floci is suitable for an `L2 SANDBOX` AWS-compatibility and failure-injection
harness. It is not an `L4 PRODUCTION` evidence lake and cannot close issue #25.

Useful test surfaces include S3 content-addressed object behavior, DynamoDB/KMS
client contracts, IAM policy paths, process separation and restart replay. These
tests must use provider-neutral AWS interfaces with an injected endpoint; core
contracts must not import Floci types.

## Production gaps

- Floci is explicitly a [local AWS emulator](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/README.md), not an external object store.
- Its [storage modes](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/configuration/storage.md) are memory or local persistent/hybrid/WAL backends, not a multi-host metadata service.
- KMS Sign/Verify is emulated; [KMS grants are not evaluated during cryptographic operations](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/kms.md).
- IAM is permissive by default and retains documented bypasses for unknown keys, unsigned requests and unmapped actions in [IAM enforcement mode](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/iam.md).
- [AWS Backup is simulated](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/backup.md); it does not copy resource data and restore jobs are unsupported.
- At the evaluated commit, the `validate-signatures` configuration is used by pre-signed URL handling; no regular Authorization-header SigV4 validation filter was found. A configured flag is not enforcement evidence.

The same adapter/harness must later run against an authorized external object
store, production metadata/index service and managed KMS/HSM, with multi-host,
backup/restore, retention and fresh-worker receipts, before #25 can advance to
`L4 PRODUCTION`.

## Local execution outcome

The local clone reached S3 write/read, WAL restart and fresh-process retrieval
before a combined security probe failed. Source inspection showed no regular
Authorization-header validation path for the configured SigV4 flag; however, no
final receipt was produced before the three-attempt stop-loss. This is a blocker,
not a successful Floci qualification. The checked-in runner now classifies only
explicit AWS signature error codes as denial, records other errors as
inconclusive, writes a quarantine receipt, and exits non-zero.
