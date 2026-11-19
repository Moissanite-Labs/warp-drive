"""warp-modeld orchestrator uniting Stages 1 to 4 with O(1) rollback and hybrid state flush."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Sequence

from .canary import CanaryResult, CanaryRunner, CanarySuite, reject_adapter_supplied_canaries
from .certificate import (
    CertificateBounds,
    FixedRadixCertificate,
    StackCertificateResult,
    verify_stack_division_free,
)
from .errors import (
    KillSwitchEngagedError,
    StateFlushError,
    UnverifiedLoraOverrideError,
    WarpError,
)
from .fingerprint import (
    AdapterBundle,
    CheckpointFingerprint,
    Plane1Lineage,
    RuntimeFlags,
    Stage1Report,
    sha256_json,
    verify_stage1,
)
from .ledger import LedgerReceipt, SignedLedger
from .llama_client import LlamaClientError, LlamaServerClient


@dataclass(frozen=True)
class MountResult:
    slot_manifest_digest: str
    active_adapters: tuple[dict[str, Any], ...]
    stage1_reports: tuple[Stage1Report, ...]
    stage2_result: StackCertificateResult
    stage3_result: CanaryResult
    slots_flushed: tuple[int, ...]
    receipt: LedgerReceipt


@dataclass(frozen=True)
class RollbackResult:
    reason: str
    kill_switch_engaged: bool
    slots_flushed: tuple[int, ...]
    elapsed_ms: float
    receipt: LedgerReceipt


class WarpModeld:
    """L3 zero-trust inference gatekeeper between L4 exo and L2 llama-server."""

    def __init__(
        self,
        *,
        pinned_checkpoint: CheckpointFingerprint,
        pinned_lineage: Plane1Lineage,
        live_runtime_flags: RuntimeFlags,
        single_bounds: CertificateBounds,
        joint_bounds: CertificateBounds,
        canary_suite: CanarySuite,
        llama_client: LlamaServerClient,
        ledger: SignedLedger,
        canary_slot_id: int = 0,
    ) -> None:
        self._lock = threading.RLock()
        self.pinned_checkpoint = pinned_checkpoint
        self.pinned_lineage = pinned_lineage
        self.live_runtime_flags = live_runtime_flags
        self.single_bounds = single_bounds
        self.joint_bounds = joint_bounds
        self.canary_suite = canary_suite
        self.llama_client = llama_client
        self.ledger = ledger
        self.canary_runner = CanaryRunner(llama_client, canary_suite, canary_slot_id=canary_slot_id)

        self._active_bundles: list[AdapterBundle] = []
        self._slot_manifest_digest: str | None = None
        self._kill_switch_engaged: bool = False
        self._learning_enabled: bool = True
        self._state_quarantined: bool = False

    def identify_checkpoint(self) -> dict[str, Any]:
        with self._lock:
            return {
                "checkpoint": self.pinned_checkpoint.to_dict(),
                "checkpoint_digest": self.pinned_checkpoint.canonical_digest(),
                "pinned_lineage": self.pinned_lineage.to_dict(),
                "lineage_digest": self.pinned_lineage.canonical_digest(),
                "runtime_flags": self.live_runtime_flags.to_dict(),
                "runtime_flags_digest": self.live_runtime_flags.canonical_digest(),
                "canary_suite_sha256": self.canary_suite.suite_sha256,
            }

    def status(self) -> dict[str, Any]:
        with self._lock:
            stale = self._is_active_stack_stale()
            return {
                "active_adapters": [b.manifest_entry() for b in self._active_bundles],
                "slot_manifest_digest": self._slot_manifest_digest,
                "kill_switch_engaged": self._kill_switch_engaged,
                "learning_enabled": self._learning_enabled,
                "state_quarantined": self._state_quarantined,
                "stale_lineage": stale,
                "checkpoint_digest": self.pinned_checkpoint.canonical_digest(),
                "lineage_digest": self.pinned_lineage.canonical_digest(),
                "runtime_flags_digest": self.live_runtime_flags.canonical_digest(),
                "ledger_head_sha256": self.ledger.head_sha256,
                "ledger_count": self.ledger.count,
            }

    def _is_active_stack_stale(self) -> bool:
        if not self._active_bundles:
            return False
        if self.pinned_lineage.contested_heads:
            return True
        for bundle in self._active_bundles:
            if bundle.source_lineage.corpus_tree_sha256 != self.pinned_lineage.corpus_tree_sha256:
                return True
            for domain, commit in bundle.source_lineage.domain_commits.items():
                if self.pinned_lineage.domain_commits.get(domain) != commit:
                    return True
        return False

    def _compute_slot_manifest_digest(self, bundles: Sequence[AdapterBundle]) -> str:
        return sha256_json(
            {
                "checkpoint_digest": self.pinned_checkpoint.canonical_digest(),
                "lineage_digest": self.pinned_lineage.canonical_digest(),
                "runtime_flags_digest": self.live_runtime_flags.canonical_digest(),
                "canary_suite_sha256": self.canary_suite.suite_sha256,
                "adapters": [b.manifest_entry() for b in bundles],
            }
        )

    def _zero_all_lora_scales(self) -> None:
        loaded = self.llama_client.list_lora_adapters()
        if loaded:
            self.llama_client.set_lora_adapters([{"id": item.id, "scale": 0.0} for item in loaded])

    def _flush_all_slots(self) -> tuple[int, ...]:
        """Erase every llama-server slot to clear both KV cache and hybrid recurrent state."""
        try:
            slots = self.llama_client.list_slots()
            flushed: list[int] = []
            for slot in slots:
                self.llama_client.erase_slot(slot.id)
                flushed.append(slot.id)
            # Re-verify zero residual recurrent state or active adapter taint.
            after = self.llama_client.list_slots()
            for slot in after:
                if slot.recurrent_state_tainted or slot.active_lora_ids or slot.n_decoded > 0:
                    raise StateFlushError(
                        f"slot {slot.id} retained residual state after erase "
                        f"(tainted={slot.recurrent_state_tainted}, active={slot.active_lora_ids}, "
                        f"n_decoded={slot.n_decoded})"
                    )
            return tuple(flushed)
        except LlamaClientError as exc:
            raise StateFlushError(f"failed to flush inference slots: {exc}") from exc

    def _record_reject(
        self,
        err: WarpError,
        *,
        adapters: Sequence[dict[str, Any]] = (),
        details: dict[str, Any] | None = None,
    ) -> LedgerReceipt:
        return self.ledger.append(
            "reject",
            checkpoint_fingerprint_sha256=self.pinned_checkpoint.canonical_digest(),
            runtime_flags_sha256=self.live_runtime_flags.canonical_digest(),
            slot_manifest_digest=self._slot_manifest_digest,
            adapters=adapters,
            stage_failed=err.stage,
            error_code=err.code,
            reason=str(err),
            details=details,
        )

    def mount_stack(
        self,
        raw_bundles: Sequence[dict[str, Any]],
        *,
        raw_composed_certificate: dict[str, Any] | None = None,
    ) -> MountResult:
        """Execute all 4 fail-closed stages before activating a single or multi-adapter stack."""
        with self._lock:
            ckpt_digest = self.pinned_checkpoint.canonical_digest()
            flags_digest = self.live_runtime_flags.canonical_digest()

            if self._state_quarantined:
                err = StateFlushError("daemon is quarantined after prior slot flush failure")
                self._record_reject(err)
                raise err

            if self._kill_switch_engaged:
                err = KillSwitchEngagedError("kill switch is engaged; refusing adapter mount")
                self._record_reject(err)
                raise err

            if not self._learning_enabled:
                err = KillSwitchEngagedError("learning is disabled; refusing adapter mount")
                self._record_reject(err)
                raise err

            if not raw_bundles:
                err = WarpError("mount stack must contain at least one adapter", code="ERR_EMPTY_STACK", stage="stage1_fingerprint")
                self._record_reject(err)
                raise err

            # Stage 0 / anti-forgery pre-check: forbid adapter-supplied canaries before parsing.
            try:
                reject_adapter_supplied_canaries(list(raw_bundles), path="bundles")
                if raw_composed_certificate is not None:
                    reject_adapter_supplied_canaries(raw_composed_certificate, path="composed_certificate")
            except WarpError as err:
                self._record_reject(err)
                raise

            # Parse bundles + Stage 1 (4-layer checkpoint + lineage + 5th runtime-flag digest).
            bundles: list[AdapterBundle] = []
            stage1_reports: list[Stage1Report] = []
            seen_llama_ids: set[int] = set()
            try:
                for raw in raw_bundles:
                    bundle = AdapterBundle.from_dict(raw)
                    if bundle.llama_adapter_id in seen_llama_ids:
                        raise WarpError(
                            f"duplicate llama_adapter_id {bundle.llama_adapter_id} in mount stack",
                            code="ERR_DUPLICATE_ADAPTER_ID",
                            stage="stage1_fingerprint",
                        )
                    seen_llama_ids.add(bundle.llama_adapter_id)
                    bundles.append(bundle)
                for bundle in bundles:
                    stage1_reports.append(
                        verify_stage1(
                            bundle,
                            self.pinned_checkpoint,
                            self.pinned_lineage,
                            self.live_runtime_flags,
                        )
                    )
            except WarpError as err:
                self._record_reject(err, adapters=[b.manifest_entry() for b in bundles])
                raise

            # Stage 2: division-free exact integer FixedRadixCertificate gate (<1ms).
            try:
                composed_cert = (
                    FixedRadixCertificate.from_dict(raw_composed_certificate)
                    if raw_composed_certificate is not None
                    else None
                )
                cert_items = [
                    (b.certificate, b.adapter_id, b.adapter_sha256, b.scale_num, b.scale_den)
                    for b in bundles
                ]
                stage2_res = verify_stack_division_free(
                    cert_items,
                    self.single_bounds,
                    self.joint_bounds,
                    expected_base_weights_sha256=self.pinned_checkpoint.weights_sha256,
                    composed_certificate=composed_cert,
                )
            except WarpError as err:
                self._record_reject(err, adapters=[b.manifest_entry() for b in bundles])
                raise

            # Stage 3: shadow-load and verifier-owned deterministic canary checks.
            try:
                currently_verified_ids = frozenset(b.llama_adapter_id for b in self._active_bundles)
                stage3_res = self.canary_runner.run(bundles, allowed_active_ids=currently_verified_ids)
            except WarpError as err:
                self._record_reject(
                    err,
                    adapters=[b.manifest_entry() for b in bundles],
                    details={"canary_suite_sha256": self.canary_suite.suite_sha256},
                )
                raise

            # Stage 4 activation: flush all live slots so previous adapter recurrent state cannot mix,
            # then apply verified scales on llama-server and write signed mount receipt.
            try:
                flushed = self._flush_all_slots()
                loaded = self.llama_client.list_lora_adapters()
                scale_by_id = {b.llama_adapter_id: b.scale_float for b in bundles}
                scale_payload = [
                    {"id": item.id, "scale": scale_by_id.get(item.id, 0.0)}
                    for item in loaded
                ]
                self.llama_client.set_lora_adapters(scale_payload)
            except (LlamaClientError, StateFlushError) as exc:
                err = exc if isinstance(exc, WarpError) else StateFlushError(f"activation failed: {exc}")
                self._state_quarantined = True
                self._active_bundles = []
                self._slot_manifest_digest = None
                self._record_reject(err, adapters=[b.manifest_entry() for b in bundles])
                raise err from exc

            manifest_digest = self._compute_slot_manifest_digest(bundles)
            self._active_bundles = list(bundles)
            self._slot_manifest_digest = manifest_digest

            receipt = self.ledger.append(
                "mount",
                checkpoint_fingerprint_sha256=ckpt_digest,
                runtime_flags_sha256=flags_digest,
                slot_manifest_digest=manifest_digest,
                adapters=[b.manifest_entry() for b in bundles],
                reason="verified_mount",
                slots_flushed=flushed,
                details={
                    "stage2_elapsed_ns": stage2_res.elapsed_ns,
                    "composed_bound_checked": stage2_res.composed_bound_checked,
                    "composed_cert_verified": stage2_res.composed_cert_verified,
                    "canary_suite_sha256": stage3_res.suite_sha256,
                    "preservation_passed": stage3_res.preservation_passed,
                    "preservation_total": stage3_res.preservation_total,
                    "canaries_passed": len(stage3_res.outcomes),
                },
            )
            return MountResult(
                slot_manifest_digest=manifest_digest,
                active_adapters=tuple(b.manifest_entry() for b in bundles),
                stage1_reports=tuple(stage1_reports),
                stage2_result=stage2_res,
                stage3_result=stage3_res,
                slots_flushed=flushed,
                receipt=receipt,
            )

    def rollback(self, reason: str = "operator_rollback", *, engage_kill_switch: bool = False) -> RollbackResult:
        """O(1) kill-switch and explicit KV + hybrid attention/SSM recurrent-state flush."""
        with self._lock:
            start = time.perf_counter()
            prior_adapters = [b.manifest_entry() for b in self._active_bundles]
            self._active_bundles = []
            self._slot_manifest_digest = None
            if engage_kill_switch:
                self._kill_switch_engaged = True

            event_name = "kill_switch" if engage_kill_switch else "rollback"
            ckpt_digest = self.pinned_checkpoint.canonical_digest()
            flags_digest = self.live_runtime_flags.canonical_digest()

            try:
                self._zero_all_lora_scales()
                flushed = self._flush_all_slots()
            except (LlamaClientError, StateFlushError) as exc:
                self._state_quarantined = True
                err = exc if isinstance(exc, StateFlushError) else StateFlushError(
                    f"rollback scale reset or slot flush failed: {exc}"
                )
                self._record_reject(
                    err,
                    adapters=prior_adapters,
                    details={"rollback_reason": reason, "kill_switch_engaged": engage_kill_switch},
                )
                raise err from exc

            elapsed_ms = (time.perf_counter() - start) * 1000.0
            receipt = self.ledger.append(
                event_name,
                checkpoint_fingerprint_sha256=ckpt_digest,
                runtime_flags_sha256=flags_digest,
                slot_manifest_digest=None,
                adapters=[],
                reason=reason,
                slots_flushed=flushed,
                details={
                    "unmounted_adapters": [a["adapter_id"] for a in prior_adapters],
                    "kill_switch_engaged": self._kill_switch_engaged,
                    "elapsed_ms": round(elapsed_ms, 3),
                },
            )
            return RollbackResult(
                reason=reason,
                kill_switch_engaged=self._kill_switch_engaged,
                slots_flushed=flushed,
                elapsed_ms=elapsed_ms,
                receipt=receipt,
            )

    def reset_kill_switch(self, operator_confirmation: str) -> dict[str, Any]:
        with self._lock:
            if self._state_quarantined:
                raise StateFlushError("cannot reset kill switch while daemon is quarantined")
            if not isinstance(operator_confirmation, str) or len(operator_confirmation.strip()) < 4:
                raise KillSwitchEngagedError("explicit operator confirmation string is required")
            self._kill_switch_engaged = False
            # Never auto-remount previous adapters; stay on clean W0 until fresh verification.
            return self.status()

    def update_pinned_lineage(self, new_lineage: Plane1Lineage) -> RollbackResult | None:
        """Update Plane 1 lineage pin; automatically unload stale or contested active stacks."""
        with self._lock:
            self.pinned_lineage = new_lineage
            if self._is_active_stack_stale():
                return self.rollback(reason="stale_lineage_auto_unload", engage_kill_switch=False)
            return None

    def set_learning_enabled(self, enabled: bool) -> RollbackResult | None:
        """Toggle parametric adapter mounting (mirrors .mep/learning off switch)."""
        with self._lock:
            self._learning_enabled = bool(enabled)
            if not self._learning_enabled and self._active_bundles:
                return self.rollback(reason="learning_disabled", engage_kill_switch=False)
            return None

    def infer(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.0,
        seed: int = 42,
        max_tokens: int = 256,
        raw_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Proxy chat completion through warp-modeld using only verified active LoRA state."""
        with self._lock:
            if self._state_quarantined:
                raise StateFlushError("refusing inference while slot state is quarantined")
            if raw_params is not None and "lora" in raw_params:
                raise UnverifiedLoraOverrideError(
                    "callers may not pass raw 'lora' overrides to warp_infer; mount through Stage 1-4 verifier"
                )
            active_lora = [
                {"id": b.llama_adapter_id, "scale": b.scale_float}
                for b in self._active_bundles
            ]
            manifest = self._slot_manifest_digest
            response = self.llama_client.chat_completion(
                messages,
                lora=active_lora,
                temperature=temperature,
                seed=seed,
                max_tokens=max_tokens,
                cache_prompt=False,
            )
            return {
                "slot_manifest_digest": manifest,
                "active_lora": active_lora,
                "response": response,
            }
