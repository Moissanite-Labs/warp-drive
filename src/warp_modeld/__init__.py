"""warp-modeld: L3 zero-trust fail-closed adapter load verifier."""

from .canary import CanaryConfigError, CanaryResult, CanaryRunner, CanarySuite, reject_adapter_supplied_canaries
from .certificate import (
    CertificateBounds,
    FixedRadixCertificate,
    RationalBound,
    StackCertificateResult,
    verify_division_free,
    verify_stack_division_free,
)
from .errors import (
    CanaryFailedError,
    CertificateError,
    CheckpointMismatchError,
    ContestedLineageError,
    ForgedCanaryError,
    KillSwitchEngagedError,
    LedgerTamperError,
    RuntimeFlagDriftError,
    StaleLineageError,
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
    verify_stage1,
)
from .ledger import HmacSha256Signer, LedgerReceipt, LedgerVerifier, SignedLedger
from .llama_client import LlamaAdapterInfo, LlamaClientError, LlamaServerClient, LlamaSlotInfo
from .verifier import MountResult, RollbackResult, WarpModeld

__all__ = [
    "AdapterBundle",
    "CanaryConfigError",
    "CanaryFailedError",
    "CanaryResult",
    "CanaryRunner",
    "CanarySuite",
    "CertificateBounds",
    "CertificateError",
    "CheckpointFingerprint",
    "CheckpointMismatchError",
    "ContestedLineageError",
    "FixedRadixCertificate",
    "ForgedCanaryError",
    "HmacSha256Signer",
    "KillSwitchEngagedError",
    "LedgerReceipt",
    "LedgerTamperError",
    "LedgerVerifier",
    "LlamaAdapterInfo",
    "LlamaClientError",
    "LlamaServerClient",
    "LlamaSlotInfo",
    "MountResult",
    "Plane1Lineage",
    "RationalBound",
    "RollbackResult",
    "RuntimeFlagDriftError",
    "RuntimeFlags",
    "SignedLedger",
    "StackCertificateResult",
    "Stage1Report",
    "StaleLineageError",
    "StateFlushError",
    "UnverifiedLoraOverrideError",
    "WarpError",
    "WarpModeld",
    "reject_adapter_supplied_canaries",
    "verify_division_free",
    "verify_stack_division_free",
    "verify_stage1",
]
