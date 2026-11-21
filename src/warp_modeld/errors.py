"""Typed fail-closed exceptions for warp-modeld."""

from __future__ import annotations


class WarpError(Exception):
    """Base fail-closed error carrying a machine-readable code and stage."""

    code: str = "ERR_WARP_INTERNAL"
    stage: str = "system"

    def __init__(self, message: str, *, code: str | None = None, stage: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        if stage is not None:
            self.stage = stage

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "stage": self.stage,
            "message": str(self),
        }


class CheckpointMismatchError(WarpError):
    code = "ERR_CHECKPOINT_MISMATCH"
    stage = "stage1_fingerprint"


class StaleLineageError(WarpError):
    code = "ERR_STALE_LINEAGE"
    stage = "stage1_fingerprint"


class ContestedLineageError(WarpError):
    code = "ERR_CONTESTED_LINEAGE"
    stage = "stage1_fingerprint"


class RuntimeFlagDriftError(WarpError):
    code = "ERR_RUNTIME_FLAG_DRIFT"
    stage = "stage1_fingerprint"


class ZoneManifestDriftError(WarpError):
    code = "ERR_ZONE_MANIFEST_DRIFT"
    stage = "stage1_fingerprint"


class CertificateError(WarpError):
    code = "ERR_CERT_INVALID"
    stage = "stage2_certificate"


class ForgedCanaryError(WarpError):
    code = "ERR_FORGED_CANARY_REJECTED"
    stage = "stage3_canary"


class CanaryFailedError(WarpError):
    code = "ERR_CANARY_FAILED"
    stage = "stage3_canary"


class StateFlushError(WarpError):
    code = "ERR_STATE_FLUSH_FAILED"
    stage = "stage4_rollback"


class LatticeFlushError(StateFlushError):
    code = "ERR_LATTICE_FLUSH_FAILED"
    stage = "stage4_rollback"


class KillSwitchEngagedError(WarpError):
    code = "ERR_KILL_SWITCH_ENGAGED"
    stage = "stage4_rollback"


class UnverifiedLoraOverrideError(WarpError):
    code = "ERR_UNVERIFIED_LORA_OVERRIDE"
    stage = "stage4_proxy"


class LedgerTamperError(WarpError):
    code = "ERR_LEDGER_TAMPERED"
    stage = "stage4_ledger"


class ControllerError(WarpError):
    code = "ERR_EXPERIMENT_CONTROLLER"
    stage = "experiment_controller"


class ContractDriftError(WarpError):
    code = "ERR_CONTRACT_DRIFT"
    stage = "experiment_contract"
