"""Opt-in live smoke test for the Cerebras Kimi K3.1 Pro client (lane 6).

Runs only when WARP_LIVE_CEREBRAS_TEST=1 and CEREBRAS_API_KEY is set.
Makes one real propose call and checks the receipt records the served
model. The test asserts nothing about the proposed candidate beyond schema
validity. A served model id that differs from the requested id makes the
client raise an error (ERR_CEREBRAS_MODEL_SUBSTITUTION), never a pass for
the requested model.

Skipped everywhere else. No credential is created by this test.
"""

from __future__ import annotations

import os
import unittest

from warp_modeld.cerebras_client import CerebrasKimiClient
from warp_modeld.errors import CerebrasClientError

LIVE = os.environ.get("WARP_LIVE_CEREBRAS_TEST") == "1" and bool(os.environ.get("CEREBRAS_API_KEY"))


@unittest.skipUnless(LIVE, "live Cerebras test needs WARP_LIVE_CEREBRAS_TEST=1 and CEREBRAS_API_KEY")
class TestLiveCerebrasSmoke(unittest.TestCase):
    def test_live_propose_records_served_model(self) -> None:
        client = CerebrasKimiClient.from_env()
        candidate, receipt = client.propose_candidate(
            {
                "task_summary": "live smoke: improve exact task score without losing retention",
                "baseline_metrics": {"task_exact": 0.61, "retention_iid": 0.88},
            }
        )
        self.assertEqual(candidate.target_layer, "last")
        self.assertEqual(receipt.provider, "cerebras")
        self.assertEqual(receipt.requested_model, client.model_id)
        # The receipt is the record. If the served id differs, the live
        # integration for the requested model is not established.
        self.assertIsNotNone(receipt.served_model)
        print(f"\nlive receipt: {receipt.to_dict()}")
        if receipt.served_model != client.model_id:
            raise AssertionError(
                f"served model {receipt.served_model!r} differs from requested {client.model_id!r}. "
                "Live integration for the requested model is UNVERIFIED."
            )


if __name__ == "__main__":
    unittest.main()
