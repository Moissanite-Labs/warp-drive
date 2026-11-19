"""Stage 1 fail-closed verification: 4-layer checkpoint, Plane 1 lineage, and 5th runtime-flag digest."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any

from .certificate import FixedRadixCertificate
from .errors import (
    CheckpointMismatchError,
    ContestedLineageError,
    RuntimeFlagDriftError,
    StaleLineageError,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize payload into deterministic canonical UTF-8 JSON bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _validate_sha256(value: str, field_name: str, exc_cls: type[Exception]) -> str:
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise exc_cls(f"{field_name} must be a 64-char lowercase hex sha256 digest")
    return value


def _validate_commit(value: str, field_name: str, exc_cls: type[Exception]) -> str:
    if not isinstance(value, str) or not COMMIT_RE.match(value):
        raise exc_cls(f"{field_name} must be a lowercase hex commit or digest (7 to 64 hex chars)")
    return value


def _require_strict_int(value: Any, field_name: str, exc_cls: type[Exception]) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise exc_cls(f"{field_name} must be an exact integer")
    return value


@dataclass(frozen=True)
class CheckpointFingerprint:
    """Layers 1 to 3 of the base checkpoint identity (layout, weights, config/tokenizer/template)."""

    model_id: str
    layout_sha256: str
    weights_sha256: str
    config_sha256: str
    tokenizer_sha256: str
    chat_template_sha256: str
    safetensors_provenance_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise CheckpointMismatchError("model_id must be a non-empty string")
        _validate_sha256(self.layout_sha256, "layout_sha256", CheckpointMismatchError)
        _validate_sha256(self.weights_sha256, "weights_sha256", CheckpointMismatchError)
        _validate_sha256(self.config_sha256, "config_sha256", CheckpointMismatchError)
        _validate_sha256(self.tokenizer_sha256, "tokenizer_sha256", CheckpointMismatchError)
        _validate_sha256(self.chat_template_sha256, "chat_template_sha256", CheckpointMismatchError)
        if self.safetensors_provenance_sha256 is not None:
            _validate_sha256(
                self.safetensors_provenance_sha256,
                "safetensors_provenance_sha256",
                CheckpointMismatchError,
            )

    def config_bundle_sha256(self) -> str:
        return sha256_json(
            {
                "config_sha256": self.config_sha256,
                "tokenizer_sha256": self.tokenizer_sha256,
                "chat_template_sha256": self.chat_template_sha256,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "layout_sha256": self.layout_sha256,
            "weights_sha256": self.weights_sha256,
            "config_sha256": self.config_sha256,
            "tokenizer_sha256": self.tokenizer_sha256,
            "chat_template_sha256": self.chat_template_sha256,
            "config_bundle_sha256": self.config_bundle_sha256(),
            "safetensors_provenance_sha256": self.safetensors_provenance_sha256,
        }

    def canonical_digest(self) -> str:
        return sha256_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckpointFingerprint:
        if not isinstance(data, dict):
            raise CheckpointMismatchError("checkpoint fingerprint must be a mapping")
        try:
            return cls(
                model_id=data["model_id"],
                layout_sha256=data["layout_sha256"],
                weights_sha256=data["weights_sha256"],
                config_sha256=data["config_sha256"],
                tokenizer_sha256=data["tokenizer_sha256"],
                chat_template_sha256=data["chat_template_sha256"],
                safetensors_provenance_sha256=data.get("safetensors_provenance_sha256"),
            )
        except KeyError as exc:
            raise CheckpointMismatchError(f"missing checkpoint fingerprint field: {exc}") from exc


@dataclass(frozen=True)
class Plane1Lineage:
    """Layer 4: pinned Plane 1 source policy lineage and contested-head state."""

    corpus_tree_sha256: str
    domain_commits: dict[str, str]
    contested_heads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_sha256(self.corpus_tree_sha256, "corpus_tree_sha256", StaleLineageError)
        if not isinstance(self.domain_commits, dict) or not self.domain_commits:
            raise StaleLineageError("domain_commits must be a non-empty mapping")
        for domain, commit in self.domain_commits.items():
            if not isinstance(domain, str) or not domain.strip():
                raise StaleLineageError("domain name must be non-empty")
            _validate_commit(commit, f"domain_commits[{domain}]", StaleLineageError)
        if not isinstance(self.contested_heads, tuple):
            object.__setattr__(self, "contested_heads", tuple(self.contested_heads))
        for head in self.contested_heads:
            if not isinstance(head, str) or not head.strip():
                raise ContestedLineageError("contested_heads entries must be non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_tree_sha256": self.corpus_tree_sha256,
            "domain_commits": dict(sorted(self.domain_commits.items())),
            "contested_heads": list(self.contested_heads),
        }

    def canonical_digest(self) -> str:
        return sha256_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Plane1Lineage:
        if not isinstance(data, dict):
            raise StaleLineageError("source_lineage must be a mapping")
        try:
            contested = data.get("contested_heads", ())
            if not isinstance(contested, (list, tuple)):
                raise ContestedLineageError("contested_heads must be a list")
            return cls(
                corpus_tree_sha256=data["corpus_tree_sha256"],
                domain_commits=dict(data["domain_commits"]),
                contested_heads=tuple(contested),
            )
        except KeyError as exc:
            raise StaleLineageError(f"missing source_lineage field: {exc}") from exc


@dataclass(frozen=True)
class RuntimeFlags:
    """Layer 5: serving runtime flags bound to adapter verification."""

    llama_server_commit: str
    quantization: str
    ctx_size: int
    kv_cache_type: str
    ctx_checkpoints: int
    swa_checkpoints: int
    lora_init_without_apply: bool = True
    rope_args: str = ""
    chat_template_args: str = ""

    def __post_init__(self) -> None:
        _validate_commit(self.llama_server_commit, "llama_server_commit", RuntimeFlagDriftError)
        if not isinstance(self.quantization, str) or not self.quantization.strip():
            raise RuntimeFlagDriftError("quantization must be a non-empty string")
        ctx = _require_strict_int(self.ctx_size, "ctx_size", RuntimeFlagDriftError)
        if ctx <= 0:
            raise RuntimeFlagDriftError("ctx_size must be positive")
        if not isinstance(self.kv_cache_type, str) or not self.kv_cache_type.strip():
            raise RuntimeFlagDriftError("kv_cache_type must be a non-empty string")
        ctx_cp = _require_strict_int(self.ctx_checkpoints, "ctx_checkpoints", RuntimeFlagDriftError)
        swa_cp = _require_strict_int(self.swa_checkpoints, "swa_checkpoints", RuntimeFlagDriftError)
        if ctx_cp < 0 or swa_cp < 0:
            raise RuntimeFlagDriftError("checkpoint counts must be non-negative")
        if not isinstance(self.lora_init_without_apply, bool):
            raise RuntimeFlagDriftError("lora_init_without_apply must be a boolean")
        if not isinstance(self.rope_args, str) or not isinstance(self.chat_template_args, str):
            raise RuntimeFlagDriftError("rope_args and chat_template_args must be strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "llama_server_commit": self.llama_server_commit,
            "quantization": self.quantization,
            "ctx_size": self.ctx_size,
            "kv_cache_type": self.kv_cache_type,
            "ctx_checkpoints": self.ctx_checkpoints,
            "swa_checkpoints": self.swa_checkpoints,
            "lora_init_without_apply": self.lora_init_without_apply,
            "rope_args": self.rope_args,
            "chat_template_args": self.chat_template_args,
        }

    def canonical_digest(self) -> str:
        return sha256_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeFlags:
        if not isinstance(data, dict):
            raise RuntimeFlagDriftError("runtime_flags must be a mapping")
        try:
            return cls(
                llama_server_commit=data["llama_server_commit"],
                quantization=data["quantization"],
                ctx_size=data["ctx_size"],
                kv_cache_type=data["kv_cache_type"],
                ctx_checkpoints=data["ctx_checkpoints"],
                swa_checkpoints=data["swa_checkpoints"],
                lora_init_without_apply=data["lora_init_without_apply"],
                rope_args=data.get("rope_args", ""),
                chat_template_args=data.get("chat_template_args", ""),
            )
        except KeyError as exc:
            raise RuntimeFlagDriftError(f"missing runtime_flags field: {exc}") from exc


@dataclass(frozen=True)
class AdapterBundle:
    """Verified input manifest describing one candidate GGUF LoRA adapter."""

    adapter_id: str
    domain: str
    llama_adapter_id: int
    adapter_sha256: str
    scale_num: int
    scale_den: int
    checkpoint: CheckpointFingerprint
    source_lineage: Plane1Lineage
    runtime_flags_sha256: str
    derivation_digest: str
    certificate: FixedRadixCertificate
    adapter_path: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not self.adapter_id.strip():
            raise CheckpointMismatchError("adapter_id must be a non-empty string")
        if not isinstance(self.domain, str) or not self.domain.strip():
            raise CheckpointMismatchError("domain must be a non-empty string")
        lid = _require_strict_int(self.llama_adapter_id, "llama_adapter_id", CheckpointMismatchError)
        if lid < 0:
            raise CheckpointMismatchError("llama_adapter_id must be non-negative")
        _validate_sha256(self.adapter_sha256, "adapter_sha256", CheckpointMismatchError)
        s_num = _require_strict_int(self.scale_num, "scale_num", CheckpointMismatchError)
        s_den = _require_strict_int(self.scale_den, "scale_den", CheckpointMismatchError)
        if s_num <= 0 or s_den <= 0:
            raise CheckpointMismatchError("scale_num and scale_den must be positive integers")
        _validate_sha256(self.runtime_flags_sha256, "runtime_flags_sha256", RuntimeFlagDriftError)
        _validate_sha256(self.derivation_digest, "derivation_digest", CheckpointMismatchError)

    @property
    def scale_float(self) -> float:
        return self.scale_num / self.scale_den

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "domain": self.domain,
            "llama_adapter_id": self.llama_adapter_id,
            "adapter_sha256": self.adapter_sha256,
            "scale_num": self.scale_num,
            "scale_den": self.scale_den,
            "derivation_digest": self.derivation_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdapterBundle:
        if not isinstance(data, dict):
            raise CheckpointMismatchError("adapter bundle must be a mapping")
        try:
            return cls(
                adapter_id=data["adapter_id"],
                domain=data["domain"],
                llama_adapter_id=data["llama_adapter_id"],
                adapter_sha256=data["adapter_sha256"],
                scale_num=data["scale_num"],
                scale_den=data["scale_den"],
                checkpoint=CheckpointFingerprint.from_dict(data["checkpoint"]),
                source_lineage=Plane1Lineage.from_dict(data["source_lineage"]),
                runtime_flags_sha256=data["runtime_flags_sha256"],
                derivation_digest=data["derivation_digest"],
                certificate=FixedRadixCertificate.from_dict(data["certificate"]),
                adapter_path=data.get("adapter_path"),
            )
        except KeyError as exc:
            raise CheckpointMismatchError(f"missing adapter bundle field: {exc}") from exc


@dataclass(frozen=True)
class Stage1Report:
    adapter_id: str
    checkpoint_digest: str
    lineage_digest: str
    runtime_flags_digest: str
    adapter_file_verified: bool


def verify_stage1(
    bundle: AdapterBundle,
    pinned_checkpoint: CheckpointFingerprint,
    pinned_lineage: Plane1Lineage,
    live_runtime_flags: RuntimeFlags,
) -> Stage1Report:
    """Verify all 4 checkpoint/lineage layers plus the 5th runtime-flag digest.

    Fails closed before any GPU memory or llama-server HTTP call is touched.
    """
    if not live_runtime_flags.lora_init_without_apply:
        raise RuntimeFlagDriftError(
            "llama-server must run with --lora-init-without-apply enabled",
            code="ERR_UNSAFE_RUNTIME_FLAGS",
        )

    if pinned_lineage.contested_heads:
        raise ContestedLineageError(
            f"pinned Plane 1 lineage has contested heads: {list(pinned_lineage.contested_heads)}"
        )
    if bundle.source_lineage.contested_heads:
        raise ContestedLineageError(
            f"adapter {bundle.adapter_id} carries contested heads: {list(bundle.source_lineage.contested_heads)}"
        )

    # Layers 1-3: checkpoint fingerprint
    checks = (
        ("model_id", bundle.checkpoint.model_id, pinned_checkpoint.model_id),
        ("layout_sha256", bundle.checkpoint.layout_sha256, pinned_checkpoint.layout_sha256),
        ("weights_sha256", bundle.checkpoint.weights_sha256, pinned_checkpoint.weights_sha256),
        ("config_sha256", bundle.checkpoint.config_sha256, pinned_checkpoint.config_sha256),
        ("tokenizer_sha256", bundle.checkpoint.tokenizer_sha256, pinned_checkpoint.tokenizer_sha256),
        ("chat_template_sha256", bundle.checkpoint.chat_template_sha256, pinned_checkpoint.chat_template_sha256),
    )
    for field_name, got, expected in checks:
        if not hmac.compare_digest(got, expected):
            raise CheckpointMismatchError(
                f"adapter {bundle.adapter_id} {field_name} mismatch: got {got}, expected {expected}"
            )

    if pinned_checkpoint.safetensors_provenance_sha256 is not None:
        got_prov = bundle.checkpoint.safetensors_provenance_sha256
        if got_prov is None or not hmac.compare_digest(got_prov, pinned_checkpoint.safetensors_provenance_sha256):
            raise CheckpointMismatchError(
                f"adapter {bundle.adapter_id} safetensors_provenance_sha256 mismatch"
            )

    # Layer 4: Plane 1 lineage (stale_lineage check)
    if not hmac.compare_digest(bundle.source_lineage.corpus_tree_sha256, pinned_lineage.corpus_tree_sha256):
        raise StaleLineageError(
            f"stale_lineage: adapter {bundle.adapter_id} corpus_tree_sha256 "
            f"{bundle.source_lineage.corpus_tree_sha256} != pinned {pinned_lineage.corpus_tree_sha256}"
        )

    if bundle.domain not in pinned_lineage.domain_commits:
        raise StaleLineageError(
            f"stale_lineage: domain '{bundle.domain}' is not pinned in active Plane 1 lineage"
        )
    if bundle.domain not in bundle.source_lineage.domain_commits:
        raise StaleLineageError(
            f"stale_lineage: adapter {bundle.adapter_id} omits commit pin for its own domain '{bundle.domain}'"
        )

    for domain, bundle_commit in bundle.source_lineage.domain_commits.items():
        if domain not in pinned_lineage.domain_commits:
            raise StaleLineageError(
                f"stale_lineage: adapter {bundle.adapter_id} references unpinned domain '{domain}'"
            )
        pinned_commit = pinned_lineage.domain_commits[domain]
        if not hmac.compare_digest(bundle_commit, pinned_commit):
            raise StaleLineageError(
                f"stale_lineage: domain '{domain}' commit {bundle_commit} != pinned {pinned_commit}"
            )

    # Layer 5: serving runtime-flag digest
    live_flags_digest = live_runtime_flags.canonical_digest()
    if not hmac.compare_digest(bundle.runtime_flags_sha256, live_flags_digest):
        raise RuntimeFlagDriftError(
            f"runtime flag drift for adapter {bundle.adapter_id}: "
            f"bundle expects {bundle.runtime_flags_sha256}, live host is {live_flags_digest}"
        )

    # Optional on-disk adapter GGUF integrity verification
    adapter_file_verified = False
    if bundle.adapter_path is not None:
        path = Path(bundle.adapter_path)
        if not path.is_file():
            raise CheckpointMismatchError(f"adapter file missing on disk: {bundle.adapter_path}")
        actual_sha = compute_file_sha256(path)
        if not hmac.compare_digest(actual_sha, bundle.adapter_sha256):
            raise CheckpointMismatchError(
                f"adapter {bundle.adapter_id} file digest mismatch: disk {actual_sha} != manifest {bundle.adapter_sha256}"
            )
        adapter_file_verified = True

    return Stage1Report(
        adapter_id=bundle.adapter_id,
        checkpoint_digest=pinned_checkpoint.canonical_digest(),
        lineage_digest=pinned_lineage.canonical_digest(),
        runtime_flags_digest=live_flags_digest,
        adapter_file_verified=adapter_file_verified,
    )
