"""Reproduce direct-constructor truthiness enabling implicit legacy KV flush."""
from types import SimpleNamespace

from warp_modeld.canary import CanaryRunner, ExternalCommandCanaryRunner
from warp_modeld.errors import StateFlushError
from warp_modeld.state_banks import STATE_BANK_KV, StateBankStatus
from warp_modeld.verifier import WarpModeld


def slot():
    return SimpleNamespace(
        id=0,
        is_processing=False,
        recurrent_state_tainted=False,
        lattice_state_tainted=False,
        ssm_state_tainted=False,
        lattice_layers_tainted=0,
        active_lora_ids=(),
        n_decoded=0,
        n_prompt_tokens_cache=0,
        state_banks={STATE_BANK_KV: StateBankStatus(STATE_BANK_KV, False)},
    )


class LegacyServer:
    base_url = "http://127.0.0.1:8080"

    def list_slots(self):
        return [slot()]

    def erase_slot(self, slot_id, *, banks=None):
        # Legacy response deliberately omits banks_flushed.
        return {"id_slot": slot_id, "erased": True}


def modeld(value):
    checkpoint = SimpleNamespace(required_state_banks=lambda: (STATE_BANK_KV,))
    return WarpModeld(
        pinned_checkpoint=checkpoint,
        pinned_lineage=None,
        live_runtime_flags=None,
        single_bounds=None,
        joint_bounds=None,
        canary_suite=None,
        llama_client=LegacyServer(),
        ledger=None,
        allow_legacy_implicit_kv_flush=value,
    )


for value in (False, "false"):
    instance = modeld(value)
    canary = CanaryRunner(LegacyServer(), None, allow_legacy_implicit_kv_flush=value)
    external = ExternalCommandCanaryRunner(
        LegacyServer(), ("true",), allow_legacy_implicit_kv_flush=value
    )
    print(
        f"input={value!r} stored_modeld={instance.allow_legacy_implicit_kv_flush!r} "
        f"stored_canary={canary.allow_legacy_implicit_kv_flush!r} "
        f"stored_external={external.allow_legacy_implicit_kv_flush!r}"
    )
    try:
        flushed, receipts = instance._flush_all_slots()
    except StateFlushError as exc:
        print(f"flush=input:{value!r} rejected={type(exc).__name__}: {exc}")
        assert value is False
    else:
        print(
            f"flush=input:{value!r} accepted slots={flushed!r} "
            f"confirmed={receipts[0].banks_confirmed!r}"
        )
        assert value == "false"
        assert flushed == (0,)
        assert receipts[0].banks_confirmed == (STATE_BANK_KV,)
