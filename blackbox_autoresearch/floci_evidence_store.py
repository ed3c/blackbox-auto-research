"""Fail-closed L2 SANDBOX evidence receipts for an AWS-shaped Floci runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from typing import Callable, Mapping

from .evidence_lake import BlobStore, S3CompatibleBlobStore


EVIDENCE_SCHEMA = "blackbox-floci-evidence-store/v1"
VERIFICATION_SCHEMA = "blackbox-floci-evidence-store-verification/v2"
PROVIDER_KIND = "floci-emulator"
MATURITY = "L2 SANDBOX"
WORKER_CONFIG_SCHEMA = "blackbox-floci-worker-config/v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat()


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _require_digest(value: str, name: str) -> None:
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be sha256:<64 lowercase hex chars>")


@dataclass(frozen=True)
class FlociEnvironment:
    commit: str
    image_id: str
    storage_mode: str
    endpoint_scheme: str
    tls_trust: str
    sigv4_validation_configured: bool
    iam_enforcement: bool

    def __post_init__(self) -> None:
        if not _COMMIT_RE.fullmatch(self.commit):
            raise ValueError("Floci commit must be a 40-character lowercase Git SHA")
        _require_digest(self.image_id, "Floci image_id")
        if self.storage_mode != "wal":
            raise ValueError("Floci sandbox evidence requires wal storage mode")
        if self.endpoint_scheme != "https":
            raise ValueError("Floci sandbox evidence requires an https endpoint")
        if self.tls_trust != "pinned-self-signed-certificate":
            raise ValueError("Floci sandbox evidence requires a pinned TLS certificate")
        if type(self.sigv4_validation_configured) is not bool or type(self.iam_enforcement) is not bool:
            raise ValueError("Floci control flags must be boolean")
        if not self.sigv4_validation_configured or not self.iam_enforcement:
            raise ValueError("Floci sandbox evidence requires SigV4 configuration and IAM enforcement")

    @property
    def digest(self) -> str:
        return _digest(_canonical(asdict(self)))


@dataclass(frozen=True)
class FlociEvidenceIdentity:
    run_id: str
    task_digest: str
    candidate_digest: str
    harness_digest: str
    evaluator_digest: str
    policy_digest: str

    def __post_init__(self) -> None:
        if not self.run_id or "/" in self.run_id or ".." in self.run_id:
            raise ValueError("run_id must be a safe non-empty identifier")
        for name in (
            "task_digest",
            "candidate_digest",
            "harness_digest",
            "evaluator_digest",
            "policy_digest",
        ):
            _require_digest(getattr(self, name), name)

    def manifest_identities(self, environment: FlociEnvironment) -> dict[str, str]:
        return {
            "task": self.task_digest,
            "candidate": self.candidate_digest,
            "environment": environment.digest,
            "harness": self.harness_digest,
            "evaluator": self.evaluator_digest,
            "policy": self.policy_digest,
        }


@dataclass(frozen=True)
class FlociWorkerConfig:
    endpoint: str
    bucket: str
    region: str
    ca_bundle: Path
    environment: FlociEnvironment
    identity: FlociEvidenceIdentity

    @classmethod
    def load(cls, path: Path) -> "FlociWorkerConfig":
        try:
            value = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid worker config: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("worker config must be an object")
        _require_exact_keys(
            value,
            {"schema", "endpoint", "bucket", "region", "ca_bundle", "environment", "identity"},
            "worker config",
        )
        if value.get("schema") != WORKER_CONFIG_SCHEMA:
            raise ValueError("worker config schema mismatch")
        environment = _require_mapping(value.get("environment"), "environment")
        identity = _require_mapping(value.get("identity"), "identity")
        try:
            result = cls(
                endpoint=str(value["endpoint"]),
                bucket=str(value["bucket"]),
                region=str(value["region"]),
                ca_bundle=Path(str(value["ca_bundle"])),
                environment=FlociEnvironment(**environment),
                identity=FlociEvidenceIdentity(**identity),
            )
        except TypeError as exc:
            raise ValueError(f"worker config fields drift: {exc}") from exc
        if not result.ca_bundle.is_file() or result.ca_bundle.is_symlink():
            raise ValueError("worker CA bundle must be a regular file")
        return result

    def store(self, environ: Mapping[str, str] | None = None) -> S3CompatibleBlobStore:
        credentials = os.environ if environ is None else environ
        access_key = credentials.get("AWS_ACCESS_KEY_ID", "")
        secret_key = credentials.get("AWS_SECRET_ACCESS_KEY", "")
        if not access_key or not secret_key:
            raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")
        context = ssl.create_default_context(cafile=str(self.ca_bundle))
        return S3CompatibleBlobStore(
            endpoint=self.endpoint,
            bucket=self.bucket,
            region=self.region,
            access_key=access_key,
            secret_key=secret_key,
            session_token=credentials.get("AWS_SESSION_TOKEN"),
            ssl_context=context,
        )


def produce_floci_evidence(
    store: BlobStore,
    payload: bytes,
    *,
    environment: FlociEnvironment,
    identity: FlociEvidenceIdentity,
    producer_pid: int | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    process_id = os.getpid() if producer_pid is None else producer_pid
    if process_id <= 0:
        raise ValueError("producer_pid must be positive")
    if not payload:
        raise ValueError("evidence payload must be non-empty")
    artifact = store.put(payload)
    return {
        "schema": EVIDENCE_SCHEMA,
        "provider_kind": PROVIDER_KIND,
        "maturity": MATURITY,
        "production_claim_allowed": False,
        "run": {"run_id": identity.run_id, "producer_pid": process_id},
        "environment": asdict(environment),
        "identities": identity.manifest_identities(environment),
        "artifact": {"digest": artifact.digest, "size": artifact.size},
        "produced_at": _timestamp(clock or (lambda: datetime.now(timezone.utc))),
    }


def _require_exact_keys(value: Mapping[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} keys drift")


def _require_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def verify_floci_evidence(
    store: BlobStore,
    manifest: Mapping[str, object],
    *,
    expected_environment: FlociEnvironment,
    expected_identity: FlociEvidenceIdentity,
    verifier_pid: int | None = None,
    run_planted_negative: bool = False,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    _require_exact_keys(
        manifest,
        {
            "schema",
            "provider_kind",
            "maturity",
            "production_claim_allowed",
            "run",
            "environment",
            "identities",
            "artifact",
            "produced_at",
        },
        "manifest",
    )
    if manifest.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError("evidence schema mismatch")
    if manifest.get("provider_kind") != PROVIDER_KIND:
        raise ValueError("provider_kind must identify the Floci emulator")
    if manifest.get("maturity") != MATURITY:
        raise ValueError("maturity must remain L2 SANDBOX")
    if manifest.get("production_claim_allowed") is not False:
        raise ValueError("production claim must remain disabled")
    produced_at = _parse_timestamp(manifest.get("produced_at"), "produced_at")
    verification_time = (clock or (lambda: datetime.now(timezone.utc)))()
    if verification_time.tzinfo is None or verification_time.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    verification_time = verification_time.astimezone(timezone.utc)
    if produced_at > verification_time:
        raise ValueError("produced_at is later than verification time")
    if manifest.get("environment") != asdict(expected_environment):
        raise ValueError("Floci environment identity drift")
    if manifest.get("identities") != expected_identity.manifest_identities(expected_environment):
        raise ValueError("evidence identities drift")

    run = _require_mapping(manifest.get("run"), "run")
    _require_exact_keys(run, {"run_id", "producer_pid"}, "run")
    if run.get("run_id") != expected_identity.run_id:
        raise ValueError("run_id drift")
    producer_pid = run.get("producer_pid")
    process_id = os.getpid() if verifier_pid is None else verifier_pid
    if type(producer_pid) is not int or producer_pid <= 0:
        raise ValueError("producer_pid must be positive")
    if process_id <= 0 or process_id == producer_pid:
        raise ValueError("fresh verifier process is required")

    artifact = _require_mapping(manifest.get("artifact"), "artifact")
    _require_exact_keys(artifact, {"digest", "size"}, "artifact")
    digest, size = artifact.get("digest"), artifact.get("size")
    if not isinstance(digest, str):
        raise ValueError("artifact digest must be a string")
    _require_digest(digest, "artifact digest")
    if type(size) is not int or size <= 0:
        raise ValueError("artifact size must be positive")
    payload = store.get(digest)
    if len(payload) != size or _digest(payload) != digest:
        raise ValueError("artifact integrity mismatch")

    local_digest_negative = "not-run"
    if run_planted_negative:
        mutated = bytes([payload[0] ^ 1]) + payload[1:]
        if _digest(mutated) == digest:
            raise ValueError("local digest mutation was not detected")
        local_digest_negative = "detected"

    return {
        "schema": VERIFICATION_SCHEMA,
        "verified": True,
        "provider_kind": PROVIDER_KIND,
        "maturity": MATURITY,
        "production_claim_allowed": False,
        "run_id": expected_identity.run_id,
        "artifact_digest": digest,
        "environment_digest": expected_environment.digest,
        "producer_pid": producer_pid,
        "verifier_pid": process_id,
        "process_separation": "verified",
        "local_digest_negative": local_digest_negative,
        "limitations": [
            "Floci is a local AWS emulator, not a production object store",
            "configured emulator controls require planted-negative outcome verification",
            "managed KMS/HSM, multi-host metadata, backup/restore, and L4 controls remain unproven",
        ],
        "verified_at": verification_time.isoformat(),
    }
