"""Explicit multi-bank recurrent state isolation model for L3 warp-modeld.

Models the three distinct cross-token state banks maintained by modern hybrid
and Latent Lattice Language Model (arXiv:2611.21608) architectures:
  - `kv_cache`: append-only softmax attention key/value entries
  - `ssm_recurrent`: native sequence-mixing states (Gated DeltaNet, Mamba-2)
  - `lattice_horizontal_streams`: per-layer horizontal computational latents
    that directly condition attention, KV-cache writes, MLP, and decoding.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .errors import StateFlushError

STATE_BANK_KV = "kv_cache"
STATE_BANK_SSM = "ssm_recurrent"
STATE_BANK_LATTICE = "lattice_horizontal_streams"

ALL_STATE_BANKS = (
    STATE_BANK_KV,
    STATE_BANK_SSM,
    STATE_BANK_LATTICE,
)
VALID_STATE_BANK_SET = frozenset(ALL_STATE_BANKS)
_ZONE_MANIFEST_ID_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class StateBankStatus:
    """Observed cleanliness and capability-tag binding for one per-slot state bank."""

    bank: str
    tainted: bool
    active_lora_ids: tuple[int, ...] = ()
    tokens_or_layers: int = 0
    capability_tag: int | None = None
    zone_manifest_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.bank, str) or self.bank not in VALID_STATE_BANK_SET:
            raise StateFlushError(f"unknown state bank: {self.bank!r}")
        if type(self.tainted) is not bool:
            raise StateFlushError("StateBankStatus.tainted must be a strict boolean")
        if not isinstance(self.active_lora_ids, tuple):
            raise StateFlushError("StateBankStatus.active_lora_ids must be a tuple of ints")
        for aid in self.active_lora_ids:
            if type(aid) is not int or aid < 0:
                raise StateFlushError(f"invalid active_lora_id in StateBankStatus: {aid!r}")
        if type(self.tokens_or_layers) is not int or self.tokens_or_layers < 0:
            raise StateFlushError("StateBankStatus.tokens_or_layers must be a non-negative exact int")
        if self.capability_tag is not None:
            if type(self.capability_tag) is not int or self.capability_tag < 0 or self.capability_tag > 255:
                raise StateFlushError("StateBankStatus.capability_tag must be an int in [0, 255]")
        if self.zone_manifest_id is not None:
            if not isinstance(self.zone_manifest_id, str) or not _ZONE_MANIFEST_ID_RE.match(self.zone_manifest_id):
                raise StateFlushError("StateBankStatus.zone_manifest_id must match sha256:<64 hex>")

    @property
    def is_clean(self) -> bool:
        return (not self.tainted) and (not self.active_lora_ids) and self.tokens_or_layers == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "bank": self.bank,
            "tainted": self.tainted,
            "active_lora_ids": list(self.active_lora_ids),
            "tokens_or_layers": self.tokens_or_layers,
            "capability_tag": self.capability_tag,
            "zone_manifest_id": self.zone_manifest_id,
            "is_clean": self.is_clean,
        }


@dataclass(frozen=True)
class BankFlushReceipt:
    """Auditable per-slot, per-bank flush record stored inside signed JSONL ledger receipts."""

    slot_id: int
    banks_requested: tuple[str, ...]
    banks_confirmed: tuple[str, ...]
    zone_manifest_id: str | None
    verified_clean: bool

    def __post_init__(self) -> None:
        if type(self.slot_id) is not int or self.slot_id < 0:
            raise StateFlushError("BankFlushReceipt.slot_id must be a non-negative exact int")
        if not isinstance(self.banks_requested, tuple) or not self.banks_requested:
            raise StateFlushError("BankFlushReceipt.banks_requested must be a non-empty tuple")
        if not isinstance(self.banks_confirmed, tuple):
            raise StateFlushError("BankFlushReceipt.banks_confirmed must be a tuple")
        for b in self.banks_requested:
            if not isinstance(b, str) or b not in VALID_STATE_BANK_SET:
                raise StateFlushError(f"invalid requested bank in BankFlushReceipt: {b!r}")
        for b in self.banks_confirmed:
            if not isinstance(b, str) or b not in VALID_STATE_BANK_SET:
                raise StateFlushError(f"invalid confirmed bank in BankFlushReceipt: {b!r}")
        if self.zone_manifest_id is not None:
            if not isinstance(self.zone_manifest_id, str) or not _ZONE_MANIFEST_ID_RE.match(self.zone_manifest_id):
                raise StateFlushError("BankFlushReceipt.zone_manifest_id must match sha256:<64 hex>")
        if type(self.verified_clean) is not bool:
            raise StateFlushError("BankFlushReceipt.verified_clean must be a strict boolean")
        if self.verified_clean:
            missing = [b for b in self.banks_requested if b not in self.banks_confirmed]
            if missing:
                raise StateFlushError(
                    f"BankFlushReceipt cannot claim verified_clean=True with unconfirmed banks: {missing}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "banks_requested": list(self.banks_requested),
            "banks_confirmed": list(self.banks_confirmed),
            "zone_manifest_id": self.zone_manifest_id,
            "verified_clean": self.verified_clean,
        }
