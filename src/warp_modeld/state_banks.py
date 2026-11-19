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
from typing import Any

STATE_BANK_KV = "kv_cache"
STATE_BANK_SSM = "ssm_recurrent"
STATE_BANK_LATTICE = "lattice_horizontal_streams"

ALL_STATE_BANKS = (
    STATE_BANK_KV,
    STATE_BANK_SSM,
    STATE_BANK_LATTICE,
)


@dataclass(frozen=True)
class StateBankStatus:
    """Observed cleanliness and capability-tag binding for one per-slot state bank."""

    bank: str
    tainted: bool
    active_lora_ids: tuple[int, ...] = ()
    tokens_or_layers: int = 0
    capability_tag: int | None = None
    zone_manifest_id: str | None = None

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "banks_requested": list(self.banks_requested),
            "banks_confirmed": list(self.banks_confirmed),
            "zone_manifest_id": self.zone_manifest_id,
            "verified_clean": self.verified_clean,
        }
