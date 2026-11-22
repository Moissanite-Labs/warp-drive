from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import unittest
from typing import Any

from warp_modeld.gameplay_gate import (
    DEFAULT_LIMITS,
    LIVE_CONFIRMED,
    MODEL_PROVEN,
    OBSERVED,
    REPLAYED,
    GateLimits,
    TrustedCheckResult,
    TrustedDomainVerification,
    TrustedNegativeControlResult,
    canonical_json_bytes,
    canonical_sha256,
    intake_gameplay_evidence,
    validate_gameplay_artifact,
)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_check(kind: str, payload: dict[str, Any], status: str = "PASS") -> dict[str, Any]:
    return {
        "kind": kind,
        "status": status,
        "checker": {
            "name": f"trusted-{kind}-checker",
            "revision": f"{kind}:pinned-test-revision",
            "artifact_sha256": sha(f"checker-bundle:{kind}"),
        },
        "source_labels": ["VERIFIED", "PRODUCER_PASS"],
        "initial_state_sha256": payload["initial_state_sha256"],
        "actions_sha256": payload["actions_sha256"],
        "trajectory_sha256": payload["trajectory_sha256"],
    }


def make_artifact() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "domain": "toy-grid/v1",
        "model": {"rules": {"move": "one orthogonal cell"}, "assumptions": ["deterministic"]},
        "initial_state": {"position": [0, 0], "goal": [1, 0]},
        "actions": [{"move": "east"}],
        "trajectory": [{"position": [0, 0]}, {"position": [1, 0]}],
        "outcome": {"goal_reached": True, "steps": 1},
    }
    for field in ("model", "initial_state", "actions", "trajectory"):
        payload[f"{field}_sha256"] = canonical_sha256(payload[field])
    # Put the digest fields in the same conceptual object; JSON key order is irrelevant.
    payload = {
        "domain": payload["domain"],
        "model": payload["model"],
        "model_sha256": payload["model_sha256"],
        "initial_state": payload["initial_state"],
        "initial_state_sha256": payload["initial_state_sha256"],
        "actions": payload["actions"],
        "actions_sha256": payload["actions_sha256"],
        "trajectory": payload["trajectory"],
        "trajectory_sha256": payload["trajectory_sha256"],
        "outcome": payload["outcome"],
    }
    raw_source = '{\n  "producer_verdict": "VERIFIED",\n  "badges": ["MODEL_PROVEN", "LIVE_CONFIRMED"]\n}'
    artifact = {
        "schema": "gameplay-evidence/v0.1",
        "artifact_sha256": sha("placeholder"),
        "producer": {
            "repository": "example/gameplay-adapter",
            "revision": "a" * 40,
            "adapter": "tests.make_artifact",
        },
        "claim": {
            "id": "route-1",
            "kind": "route",
            "statement": "Moving east reaches the goal in one step.",
        },
        "mechanics": [
            {
                "id": "grid-rules",
                "path": "profiles/toy/rules.yaml",
                "source_revision": "b" * 40,
                "raw_sha256": sha("raw simgrammar yaml"),
            }
        ],
        "payload": payload,
        "evidence": {
            "checks": [
                make_check("model_replay", payload),
                make_check("model_proof", payload),
                make_check("live_execution", payload),
            ],
            "negative_controls": [
                {
                    "name": "illegal-west-move",
                    "mutation": {"action": {"move": "west"}, "expected": "reject"},
                    "observed": {"rejected": True, "reason": "wall"},
                    "passed": True,
                }
            ],
            "limitations": ["Only the toy-grid transition is covered; no real game engine was run by this fixture."],
        },
        "source": {
            "media_type": "application/json",
            "raw_sha256": hashlib.sha256(raw_source.encode("utf-8")).hexdigest(),
            "raw": raw_source,
        },
    }
    refresh_artifact(artifact)
    return artifact


def refresh_artifact(artifact: dict[str, Any]) -> None:
    body = {key: value for key, value in artifact.items() if key != "artifact_sha256"}
    artifact["artifact_sha256"] = canonical_sha256(body)


def refresh_source(artifact: dict[str, Any]) -> None:
    artifact["source"]["raw_sha256"] = hashlib.sha256(artifact["source"]["raw"].encode("utf-8")).hexdigest()
    refresh_artifact(artifact)


def refresh_payload(artifact: dict[str, Any], *, update_checks: bool = True) -> None:
    payload = artifact["payload"]
    for field in ("model", "initial_state", "actions", "trajectory"):
        payload[f"{field}_sha256"] = canonical_sha256(payload[field])
    if update_checks:
        for check in artifact["evidence"]["checks"]:
            for field in ("initial_state_sha256", "actions_sha256", "trajectory_sha256"):
                check[field] = payload[field]
    refresh_artifact(artifact)


def trusted_results(
    artifact: dict[str, Any],
    *,
    kinds: set[str] | None = None,
    include_controls: bool = True,
) -> TrustedDomainVerification:
    checks = tuple(
        TrustedCheckResult(canonical_sha256(check), True, (f"independent {check['kind']} reproduced",))
        for check in artifact["evidence"]["checks"]
        if kinds is None or check["kind"] in kinds
    )
    controls = (
        tuple(
            TrustedNegativeControlResult(canonical_sha256(control), True)
            for control in artifact["evidence"]["negative_controls"]
        )
        if include_controls
        else ()
    )
    return TrustedDomainVerification(artifact["artifact_sha256"], checks, controls, ("domain intake complete",))


def intake(artifact: dict[str, Any], **kwargs: Any):
    return intake_gameplay_evidence(json.dumps(artifact, ensure_ascii=True), **kwargs)


def codes(result: Any) -> set[str]:
    return {finding.code for finding in result.findings}


class GameplayGateValidTests(unittest.TestCase):
    def test_valid_artifact_defaults_to_observed_only(self) -> None:
        result = intake(make_artifact())
        self.assertTrue(result.envelope_valid)
        self.assertTrue(result.valid)
        self.assertEqual(result.source_badges, (OBSERVED, REPLAYED, MODEL_PROVEN, LIVE_CONFIRMED))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertEqual(result.badges, (OBSERVED,))
        self.assertIsNone(result.verification_valid)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.unresolved_differences), 3)
        self.assertIn("VERIFIED", result.source_findings[0].message)
        serialized = result.to_dict()
        self.assertEqual(serialized["admitted_badges"], [OBSERVED])
        self.assertEqual(serialized["limits"], DEFAULT_LIMITS.to_dict())
        json.dumps(serialized)

    def test_all_trusted_results_admit_each_badge_independently(self) -> None:
        artifact = make_artifact()
        result = intake(artifact, verifier_results=trusted_results(artifact))
        self.assertTrue(result.envelope_valid)
        self.assertTrue(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED, REPLAYED, MODEL_PROVEN, LIVE_CONFIRMED))
        self.assertEqual(result.unresolved_differences, ())
        self.assertIn("DOMAIN_VERIFIER_FINDING", codes(result))

    def test_callback_results_have_the_same_binding_requirements(self) -> None:
        artifact = make_artifact()
        calls: list[dict[str, Any]] = []

        def verifier(received: dict[str, Any]) -> TrustedDomainVerification:
            calls.append(received)
            received["claim"]["statement"] = "mutation of verifier input cannot mutate gate artifact"
            return trusted_results(artifact)

        result = intake(artifact, verifier=verifier)
        self.assertEqual(result.admitted_badges, (OBSERVED, REPLAYED, MODEL_PROVEN, LIVE_CONFIRMED))
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0]["claim"]["statement"], artifact["claim"]["statement"])

    def test_replay_only_verification_does_not_fabricate_proof_or_live(self) -> None:
        artifact = make_artifact()
        result = intake(artifact, verifier_results=trusted_results(artifact, kinds={"model_replay"}))
        self.assertEqual(result.admitted_badges, (OBSERVED, REPLAYED))
        self.assertTrue(result.verification_valid)
        self.assertIn("MISSING_CHECK_VERIFICATION", codes(result))
        self.assertEqual(len(result.unresolved_differences), 2)

    def test_observation_without_checks_or_controls_is_valid(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["checks"] = []
        artifact["evidence"]["negative_controls"] = []
        refresh_artifact(artifact)
        result = intake(artifact)
        self.assertTrue(result.envelope_valid)
        self.assertEqual(result.source_badges, (OBSERVED,))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertEqual(result.unresolved_differences, ())

    def test_raw_source_is_data_not_parsed_or_executed(self) -> None:
        artifact = make_artifact()
        artifact["source"]["raw"] = (
            '["__import__(\'os\').system(\'do-not-run\')", ' + "[" * 1000 + "0" + "]" * 1000 + "]"
        )
        # Deliberately malformed JSON and duplicate-looking text remain opaque raw bytes.
        artifact["source"]["raw"] += ' {"status":"PASS","status":"FAIL"}'
        refresh_source(artifact)
        result = intake(artifact)
        self.assertTrue(result.envelope_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))

    def test_exact_utf8_source_formatting_is_committed(self) -> None:
        artifact = make_artifact()
        artifact["source"]["raw"] = '{\n\t"message": "snowman [3m☃[0m and 汉字", "n": 1.0\n}'
        refresh_source(artifact)
        self.assertTrue(intake(artifact).envelope_valid)
        artifact["source"]["raw"] = artifact["source"]["raw"].replace("1.0", "1")
        result = intake(artifact)
        self.assertFalse(result.envelope_valid)
        self.assertIn("DIGEST_MISMATCH", codes(result))

    def test_validation_alias_and_dataclass_or_mapping_results(self) -> None:
        artifact = make_artifact()
        raw = json.dumps(artifact)
        trusted = trusted_results(artifact, kinds={"model_replay"})
        as_mapping = {
            "artifact_sha256": trusted.artifact_sha256,
            "checks": [
                {"check_sha256": result.check_sha256, "passed": result.passed, "findings": list(result.findings)}
                for result in trusted.checks
            ],
            "negative_controls": [
                {"control_sha256": result.control_sha256, "passed": result.passed}
                for result in trusted.negative_controls
            ],
        }
        result = validate_gameplay_artifact(raw, verifier_results=as_mapping)
        self.assertEqual(result.admitted_badges, (OBSERVED, REPLAYED))


class GameplayGateJsonAndLimitTests(unittest.TestCase):
    def assertInvalid(self, result: Any, code: str) -> None:
        self.assertFalse(result.envelope_valid)
        self.assertEqual(result.source_badges, ())
        self.assertEqual(result.admitted_badges, ())
        self.assertIn(code, codes(result), result.findings)

    def test_malformed_json(self) -> None:
        for raw in ("{", "", "[1,2", '{"unterminated": }'):
            with self.subTest(raw=raw):
                self.assertInvalid(intake_gameplay_evidence(raw), "MALFORMED_JSON")

    def test_invalid_utf8_and_document_type(self) -> None:
        self.assertInvalid(intake_gameplay_evidence(b"\xff{}"), "MALFORMED_JSON")
        self.assertInvalid(intake_gameplay_evidence(123), "DOCUMENT_TYPE")  # type: ignore[arg-type]
        self.assertInvalid(intake_gameplay_evidence('{"x":"\ud800"}'), "INVALID_UTF8")

    def test_duplicate_json_key_at_top_level(self) -> None:
        raw = json.dumps(make_artifact(), separators=(",", ":"))
        raw = raw.replace('"schema":"gameplay-evidence/v0.1"', '"schema":"gameplay-evidence/v0.1","schema":"gameplay-evidence/v0.1"', 1)
        self.assertInvalid(intake_gameplay_evidence(raw), "DUPLICATE_JSON_KEY")

    def test_duplicate_json_key_in_nested_object(self) -> None:
        raw = json.dumps(make_artifact(), separators=(",", ":"))
        raw = raw.replace('"status":"PASS"', '"status":"PASS","status":"FAIL"', 1)
        self.assertInvalid(intake_gameplay_evidence(raw), "DUPLICATE_JSON_KEY")

    def test_deep_payload_is_rejected_before_canonicalization(self) -> None:
        artifact = make_artifact()
        deep: Any = {"leaf": True}
        for _ in range(DEFAULT_LIMITS.max_depth + 5):
            deep = [deep]
        artifact["payload"]["outcome"] = {"deep": deep}
        self.assertInvalid(intake(artifact), "DEPTH_LIMIT")

    def test_json_decoder_recursion_failure_is_contained(self) -> None:
        raw = "[" * 3000 + "0" + "]" * 3000
        result = intake_gameplay_evidence(raw)
        self.assertFalse(result.envelope_valid)
        self.assertTrue(codes(result).intersection({"MALFORMED_JSON", "DEPTH_LIMIT"}))

    def test_oversized_document_is_rejected_before_decode(self) -> None:
        raw = b" " * (DEFAULT_LIMITS.max_bytes + 1)
        self.assertInvalid(intake_gameplay_evidence(raw), "BYTE_LIMIT")

    def test_array_string_object_and_total_limits(self) -> None:
        cases: list[tuple[GateLimits, Any, str]] = []
        array_artifact = make_artifact()
        array_artifact["payload"]["actions"] = [0, 1, 2, 3]
        cases.append((GateLimits(max_array_items=3), array_artifact, "ARRAY_LIMIT"))

        string_artifact = make_artifact()
        string_artifact["claim"]["statement"] = "x" * 100
        cases.append((GateLimits(max_string_bytes=20), string_artifact, "STRING_LIMIT"))

        object_artifact = make_artifact()
        object_artifact["payload"]["outcome"] = {str(i): i for i in range(4)}
        cases.append((GateLimits(max_object_keys=3), object_artifact, "OBJECT_KEY_LIMIT"))

        total_artifact = make_artifact()
        total_artifact["payload"]["outcome"] = {"a": [1, 2, 3], "b": [4, 5, 6]}
        cases.append((GateLimits(max_total_items=10), total_artifact, "TOTAL_ITEM_LIMIT"))

        total_string_artifact = make_artifact()
        total_string_artifact["claim"]["statement"] = "x" * 100
        cases.append((GateLimits(max_total_string_bytes=100), total_string_artifact, "TOTAL_STRING_LIMIT"))
        for limits, artifact, code in cases:
            with self.subTest(code=code):
                self.assertInvalid(intake(artifact, limits=limits), code)

    def test_negative_control_check_and_mechanic_count_limits(self) -> None:
        for field, limit_name in (
            ("checks", "max_checks"),
            ("negative_controls", "max_negative_controls"),
        ):
            artifact = make_artifact()
            values = artifact["evidence"][field]
            artifact["evidence"][field] = values * 3
            limits = GateLimits(**{limit_name: 2})
            with self.subTest(field=field):
                self.assertInvalid(intake(artifact, limits=limits), "ARRAY_LIMIT")
        artifact = make_artifact()
        artifact["mechanics"] *= 3
        self.assertInvalid(intake(artifact, limits=GateLimits(max_mechanics=2)), "ARRAY_LIMIT")

    def test_invalid_limits_and_explicit_type_checks(self) -> None:
        for value in (True, 0, -1, 1.5, "3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    GateLimits(max_depth=value)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            intake_gameplay_evidence("{}", limits={})  # type: ignore[arg-type]


class GameplayGateCanonicalTests(unittest.TestCase):
    def assertInvalid(self, result: Any, code: str) -> None:
        self.assertFalse(result.envelope_valid)
        self.assertEqual(result.admitted_badges, ())
        self.assertIn(code, codes(result), result.findings)

    def test_canonical_json_is_sorted_compact_ascii(self) -> None:
        self.assertEqual(canonical_json_bytes({"z": "汉", "a": [1, True, None]}), b'{"a":[1,true,null],"z":"\\u6c49"}')

    def test_signed_64_bit_boundaries(self) -> None:
        for value in (-(1 << 63), (1 << 63) - 1):
            artifact = make_artifact()
            artifact["payload"]["outcome"]["number"] = value
            refresh_payload(artifact)
            with self.subTest(value=value):
                self.assertTrue(intake(artifact).envelope_valid)
        for value in (-(1 << 63) - 1, 1 << 63):
            artifact = make_artifact()
            artifact["payload"]["outcome"]["number"] = value
            with self.subTest(value=value):
                self.assertInvalid(intake(artifact), "INT64_RANGE")
                with self.assertRaises(ValueError):
                    canonical_json_bytes({"n": value})

    def test_every_float_is_rejected(self) -> None:
        for value in (1.0, 1.5, float("inf"), float("-inf"), float("nan"), float(1 << 63)):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    canonical_json_bytes({"n": value})
                artifact = make_artifact()
                artifact["payload"]["outcome"]["number"] = value
                # Do not refresh commitments: canonicalization itself must reject
                # the float, and intake must still contain it as a validation error.
                self.assertInvalid(
                    intake(artifact),
                    "MALFORMED_JSON" if value in (float("inf"), float("-inf")) or value != value else "FLOAT_NUMBER",
                )

    def test_json_non_finite_constants_are_rejected(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                self.assertInvalid(intake_gameplay_evidence('{"n":' + constant + "}"), "MALFORMED_JSON")

    def test_bools_are_not_accepted_as_schema_integers_or_verdicts(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["negative_controls"][0]["passed"] = 1
        self.assertInvalid(intake(artifact), "BOOLEAN_REQUIRED")
        artifact = make_artifact()
        artifact["evidence"]["checks"][1]["status"] = True
        self.assertInvalid(intake(artifact), "CHECK_STATUS")
        trusted = trusted_results(make_artifact())
        result = intake(
            make_artifact(),
            verifier_results={
                "artifact_sha256": trusted.artifact_sha256,
                "checks": [{"check_sha256": trusted.checks[0].check_sha256, "passed": 1}],
                "negative_controls": [],
            },
        )
        self.assertFalse(result.verification_valid)
        self.assertIn("VERIFIER_RESULT_BOOLEAN", codes(result))

    def test_non_string_keys_and_non_json_python_values(self) -> None:
        for value in ({1: "x"}, {"x": b"bytes"}, {"x": {1, 2}}, {"x": "\ud800"}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    canonical_json_bytes(value)


class GameplayGateDigestTests(unittest.TestCase):
    def assertInvalid(self, result: Any, code: str) -> None:
        self.assertFalse(result.envelope_valid)
        self.assertEqual(result.admitted_badges, ())
        self.assertIn(code, codes(result), result.findings)

    def test_self_digest_tamper(self) -> None:
        artifact = make_artifact()
        artifact["claim"]["statement"] = "forged stronger statement"
        result = intake(artifact)
        self.assertInvalid(result, "DIGEST_MISMATCH")
        self.assertTrue(any(f.path == "$.artifact_sha256" for f in result.findings))

    def test_zero_and_noncanonical_self_digests(self) -> None:
        for value in ("0" * 64, "A" * 64, "abc", 123):
            artifact = make_artifact()
            artifact["artifact_sha256"] = value
            with self.subTest(value=value):
                self.assertInvalid(intake(artifact), "SHA256")

    def test_raw_source_tamper_is_rejected(self) -> None:
        artifact = make_artifact()
        artifact["source"]["raw"] = artifact["source"]["raw"].replace("VERIFIED", "FORGED")
        result = intake(artifact)
        self.assertInvalid(result, "DIGEST_MISMATCH")
        paths = {finding.path for finding in result.findings}
        self.assertIn("$.source.raw_sha256", paths)
        self.assertIn("$.artifact_sha256", paths)

    def test_rebound_raw_source_still_needs_new_trusted_results(self) -> None:
        artifact = make_artifact()
        old_results = trusted_results(artifact)
        artifact["source"]["raw"] = artifact["source"]["raw"].replace("VERIFIED", "FORGED")
        refresh_source(artifact)
        default = intake(artifact)
        self.assertTrue(default.envelope_valid)
        self.assertEqual(default.admitted_badges, (OBSERVED,))
        verified = intake(artifact, verifier_results=old_results)
        self.assertFalse(verified.verification_valid)
        self.assertEqual(verified.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIER_ARTIFACT_MISMATCH", codes(verified))

    def test_each_payload_commitment_detects_tampering(self) -> None:
        for field, value in (
            ("model", {"rules": {"move": "teleport"}}),
            ("initial_state", {"position": [9, 9]}),
            ("actions", [{"move": "teleport"}]),
            ("trajectory", [{"position": [9, 9]}]),
        ):
            artifact = make_artifact()
            artifact["payload"][field] = value
            with self.subTest(field=field):
                result = intake(artifact)
                self.assertInvalid(result, "DIGEST_MISMATCH")
                self.assertTrue(any(f.path == f"$.payload.{field}_sha256" for f in result.findings))

    def test_each_check_commitment_must_match_payload(self) -> None:
        for field in ("initial_state_sha256", "actions_sha256", "trajectory_sha256"):
            for index in range(3):
                artifact = make_artifact()
                artifact["evidence"]["checks"][index][field] = sha("forged commitment")
                refresh_artifact(artifact)
                with self.subTest(field=field, index=index):
                    result = intake(artifact)
                    self.assertInvalid(result, "CHECK_COMMITMENT_MISMATCH")

    def test_payload_change_cannot_leave_old_check_commitments(self) -> None:
        artifact = make_artifact()
        artifact["payload"]["trajectory"] = [{"position": [9, 9]}]
        refresh_payload(artifact, update_checks=False)
        result = intake(artifact)
        self.assertInvalid(result, "CHECK_COMMITMENT_MISMATCH")
        self.assertEqual(result.source_badges, ())

    def test_old_verifier_results_cannot_follow_rebound_model_or_live_run(self) -> None:
        artifact = make_artifact()
        old_results = trusted_results(artifact)
        artifact["payload"]["model"]["rules"]["move"] = "teleport"
        artifact["payload"]["trajectory"] = [{"position": [99, 99]}]
        refresh_payload(artifact, update_checks=True)
        result = intake(artifact, verifier_results=old_results)
        self.assertTrue(result.envelope_valid)
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIER_ARTIFACT_MISMATCH", codes(result))


class GameplayGateSchemaMutationTests(unittest.TestCase):
    def test_unknown_or_missing_keys_fail_at_every_exact_object_boundary(self) -> None:
        mutations = [
            lambda a: a.update({"admitted_badges": [LIVE_CONFIRMED]}),
            lambda a: a["producer"].update({"trusted": True}),
            lambda a: a["claim"].pop("statement"),
            lambda a: a["mechanics"][0].pop("raw_sha256"),
            lambda a: a["payload"].update({"proof": "PASS"}),
            lambda a: a["evidence"].pop("limitations"),
            lambda a: a["evidence"]["checks"][0].update({"verified": True}),
            lambda a: a["evidence"]["checks"][0]["checker"].pop("artifact_sha256"),
            lambda a: a["evidence"]["negative_controls"][0].update({"source_PASS": True}),
            lambda a: a["source"].pop("raw"),
        ]
        for index, mutate in enumerate(mutations):
            artifact = make_artifact()
            mutate(artifact)
            with self.subTest(index=index):
                result = intake(artifact)
                self.assertFalse(result.envelope_valid)
                self.assertIn("OBJECT_KEYS", codes(result))

    def test_wrong_payload_and_evidence_container_types(self) -> None:
        mutations = [
            lambda a: a["payload"].update(model=[]),
            lambda a: a["payload"].update(initial_state=[]),
            lambda a: a["payload"].update(outcome=[]),
            lambda a: a["payload"].update(actions={}),
            lambda a: a["payload"].update(trajectory={}),
            lambda a: a["evidence"].update(limitations=[]),
            lambda a: a["evidence"].update(limitations=[""]),
            lambda a: a["evidence"].update(checks={}),
            lambda a: a["evidence"].update(negative_controls={}),
            lambda a: a.update(mechanics={}),
        ]
        for index, mutate in enumerate(mutations):
            artifact = make_artifact()
            mutate(artifact)
            with self.subTest(index=index):
                self.assertFalse(intake(artifact).envelope_valid)

    def test_identifiers_commits_repository_and_mechanic_paths(self) -> None:
        mutations = [
            (lambda a: a["producer"].update(repository="owner"), "REPOSITORY"),
            (lambda a: a["producer"].update(revision="a" * 39), "COMMIT"),
            (lambda a: a["producer"].update(revision="A" * 40), "COMMIT"),
            (lambda a: a["mechanics"][0].update(source_revision="xyz"), "COMMIT"),
            (lambda a: a["claim"].update(id="not ascii 汉"), "ASCII_IDENTIFIER"),
            (lambda a: a["payload"].update(domain="has space"), "ASCII_IDENTIFIER"),
            (lambda a: a["mechanics"][0].update(path="../rules.yaml"), "MECHANIC_PATH"),
            (lambda a: a["mechanics"][0].update(path="/rules.yaml"), "MECHANIC_PATH"),
            (lambda a: a["mechanics"][0].update(path="rules.json"), "MECHANIC_PATH"),
            (lambda a: a["mechanics"][0].update(raw_sha256="0" * 64), "SHA256"),
        ]
        for index, (mutate, code) in enumerate(mutations):
            artifact = make_artifact()
            mutate(artifact)
            with self.subTest(index=index):
                result = intake(artifact)
                self.assertFalse(result.envelope_valid)
                self.assertIn(code, codes(result))

    def test_schema_claim_check_and_control_values(self) -> None:
        mutations = [
            (lambda a: a.update(schema="gameplay-evidence/v0.2"), "SCHEMA"),
            (lambda a: a["claim"].update(kind="proof"), "CLAIM_KIND"),
            (lambda a: a["claim"].update(kind=[]), "CLAIM_KIND"),
            (lambda a: a["evidence"]["checks"][0].update(kind="live_proof"), "CHECK_KIND"),
            (lambda a: a["evidence"]["checks"][0].update(status=[]), "CHECK_STATUS"),
            (lambda a: a["evidence"]["checks"][0].update(source_labels=[""]), "NONEMPTY_STRING"),
            (lambda a: a["evidence"]["negative_controls"][0].update(passed="PASS"), "BOOLEAN_REQUIRED"),
            (lambda a: a["source"].update(raw=""), "SOURCE_RAW"),
        ]
        for index, (mutate, code) in enumerate(mutations):
            artifact = make_artifact()
            mutate(artifact)
            with self.subTest(index=index):
                result = intake(artifact)
                self.assertFalse(result.envelope_valid)
                self.assertIn(code, codes(result))


class GameplayGateTrustMutationTests(unittest.TestCase):
    def test_missing_checker_pin_fails_even_with_forged_trusted_pass(self) -> None:
        for field in ("name", "revision", "artifact_sha256"):
            artifact = make_artifact()
            artifact["evidence"]["checks"][0]["checker"][field] = ""
            with self.subTest(field=field):
                result = intake(artifact, verifier_results=trusted_results(make_artifact()))
                self.assertFalse(result.envelope_valid)
                self.assertEqual(result.admitted_badges, ())

    def test_dropped_negative_controls_remove_higher_source_and_admitted_badges(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["negative_controls"] = []
        refresh_artifact(artifact)
        result = intake(artifact, verifier_results=trusted_results(artifact))
        self.assertEqual(result.source_badges, (OBSERVED,))
        self.assertEqual(result.admitted_badges, (OBSERVED,))

    def test_missing_trusted_negative_controls_fail_closed(self) -> None:
        artifact = make_artifact()
        result = intake(artifact, verifier_results=trusted_results(artifact, include_controls=False))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("MISSING_NEGATIVE_CONTROL_VERIFICATION", codes(result))

    def test_source_fail_control_cannot_be_replaced_by_importer_pass(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["negative_controls"][0]["passed"] = False
        refresh_artifact(artifact)
        result = intake(artifact, verifier_results=trusted_results(artifact))
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("SOURCE_IMPORTER_CONFLICT", codes(result))
        self.assertTrue(any(f.code == "SOURCE_IMPORTER_CONFLICT" for f in result.unresolved_differences))

    def test_verified_text_and_forged_labels_never_promote(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["checks"][0]["source_labels"] = [
            "VERIFIED",
            "MODEL_PROVEN",
            "LIVE_CONFIRMED",
            "PASS",
        ]
        artifact["evidence"]["checks"][0]["status"] = "FAIL"
        artifact["evidence"]["checks"][1]["status"] = "FAIL"
        artifact["evidence"]["checks"][2]["status"] = "FAIL"
        refresh_artifact(artifact)
        result = intake(artifact)
        self.assertEqual(result.source_badges, (OBSERVED,))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIED", result.source_findings[0].message)

    def test_any_source_fail_vetoes_higher_source_badges(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["checks"][1]["status"] = "FAIL"
        refresh_artifact(artifact)
        result = intake(artifact)
        self.assertEqual(result.source_badges, (OBSERVED,))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertTrue(any(f.code == "SOURCE_CHECK" and "FAIL" in f.message for f in result.source_findings))

    def test_independent_pass_cannot_aggregate_around_source_fail(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["checks"][2]["status"] = "FAIL"
        refresh_artifact(artifact)
        # Deliberately omit trusted results for the failed live check.  Even
        # otherwise complete replay/proof verification cannot erase the veto.
        result = intake(
            artifact,
            verifier_results=trusted_results(artifact, kinds={"model_replay", "model_proof"}),
        )
        self.assertTrue(result.verification_valid)
        self.assertEqual(result.source_badges, (OBSERVED,))
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("SOURCE_FAIL_VETO", codes(result))

    def test_verifier_exception_suppresses_every_higher_badge(self) -> None:
        def broken_verifier(_: dict[str, Any]) -> TrustedDomainVerification:
            raise RuntimeError("domain adapter crashed")

        result = intake(make_artifact(), verifier=broken_verifier)
        self.assertTrue(result.envelope_valid)
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIER_EXCEPTION", codes(result))
        self.assertIn("RuntimeError", result.findings[0].message)

    def test_invalid_envelope_never_invokes_verifier(self) -> None:
        artifact = make_artifact()
        artifact["claim"]["statement"] = "tampered"
        called = False

        def verifier(_: dict[str, Any]) -> TrustedDomainVerification:
            nonlocal called
            called = True
            return trusted_results(artifact)

        result = intake(artifact, verifier=verifier)
        self.assertFalse(result.envelope_valid)
        self.assertFalse(called)

    def test_result_verifier_error_is_not_a_negative_verdict(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        errored = TrustedDomainVerification(
            trusted.artifact_sha256,
            (TrustedCheckResult(trusted.checks[0].check_sha256, False, error="checker unavailable"),) + trusted.checks[1:],
            trusted.negative_controls,
        )
        result = intake(artifact, verifier_results=errored)
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIER_ERROR", codes(result))

    def test_control_verifier_error_fails_all_higher_badges(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        errored = TrustedDomainVerification(
            trusted.artifact_sha256,
            trusted.checks,
            (TrustedNegativeControlResult(trusted.negative_controls[0].control_sha256, False, error="control crashed"),),
        )
        result = intake(artifact, verifier_results=errored)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertFalse(result.verification_valid)
        self.assertIn("VERIFIER_ERROR", codes(result))

    def test_errored_result_cannot_also_pass(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        result = intake(
            artifact,
            verifier_results={
                "artifact_sha256": artifact["artifact_sha256"],
                "checks": [
                    {
                        "check_sha256": trusted.checks[0].check_sha256,
                        "passed": True,
                        "error": "contradiction",
                    }
                ],
                "negative_controls": [
                    {"control_sha256": trusted.negative_controls[0].control_sha256, "passed": True}
                ],
            },
        )
        self.assertFalse(result.verification_valid)
        self.assertIn("VERIFIER_RESULT_CONTRADICTION", codes(result))
        self.assertEqual(result.admitted_badges, (OBSERVED,))

    def test_unknown_or_rebound_check_result_is_rejected(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        forged = deepcopy(trusted.checks[0].__dict__)
        forged["check_sha256"] = sha("not a source check")
        result = intake(
            artifact,
            verifier_results={
                "artifact_sha256": artifact["artifact_sha256"],
                "checks": [forged],
                "negative_controls": [
                    {"control_sha256": trusted.negative_controls[0].control_sha256, "passed": True}
                ],
            },
        )
        self.assertFalse(result.verification_valid)
        self.assertIn("UNKNOWN_VERIFIER_CHECK", codes(result))
        self.assertEqual(result.admitted_badges, (OBSERVED,))

    def test_artifact_binding_must_be_lowercase_sha_and_exact(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        for binding in ("é" * 64, "A" * 64, sha("different")):
            with self.subTest(binding=binding):
                result = intake(
                    artifact,
                    verifier_results={
                        "artifact_sha256": binding,
                        "checks": [check.__dict__ for check in trusted.checks],
                        "negative_controls": [control.__dict__ for control in trusted.negative_controls],
                    },
                )
                self.assertFalse(result.verification_valid)
                self.assertIn("VERIFIER_ARTIFACT_MISMATCH", codes(result))

    def test_duplicate_unknown_and_malformed_verifier_results(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        duplicate = TrustedDomainVerification(
            artifact["artifact_sha256"],
            (trusted.checks[0], trusted.checks[0]),
            trusted.negative_controls,
        )
        result = intake(artifact, verifier_results=duplicate)
        self.assertFalse(result.verification_valid)
        self.assertIn("DUPLICATE_VERIFIER_RESULT", codes(result))

        malformed = {
            "artifact_sha256": artifact["artifact_sha256"],
            "checks": [{"check_sha256": trusted.checks[0].check_sha256, "passed": True, "extra": True}],
            "negative_controls": [],
        }
        result = intake(artifact, verifier_results=malformed)
        self.assertFalse(result.verification_valid)
        self.assertIn("VERIFIER_RESULT_KEYS", codes(result))

    def test_source_fail_cannot_be_replaced_by_importer_pass(self) -> None:
        artifact = make_artifact()
        artifact["evidence"]["checks"][0]["status"] = "FAIL"
        refresh_artifact(artifact)
        result = intake(artifact, verifier_results=trusted_results(artifact))
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("SOURCE_IMPORTER_CONFLICT", codes(result))
        self.assertTrue(any(f.code == "SOURCE_CHECK" and "FAIL" in f.message for f in result.source_findings))

    def test_false_live_verdict_does_not_destroy_independent_replay_and_proof(self) -> None:
        artifact = make_artifact()
        trusted = trusted_results(artifact)
        checks = tuple(
            TrustedCheckResult(result.check_sha256, False) if i == 2 else result
            for i, result in enumerate(trusted.checks)
        )
        result = intake(
            artifact,
            verifier_results=TrustedDomainVerification(
                trusted.artifact_sha256, checks, trusted.negative_controls, trusted.findings
            ),
        )
        self.assertTrue(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED, REPLAYED, MODEL_PROVEN))
        self.assertEqual(result.source_badges, (OBSERVED, REPLAYED, MODEL_PROVEN, LIVE_CONFIRMED))

    def test_supplying_both_verifier_forms_fails_closed(self) -> None:
        artifact = make_artifact()
        result = intake(
            artifact,
            verifier_results=trusted_results(artifact),
            verifier=lambda _: trusted_results(artifact),
        )
        self.assertFalse(result.verification_valid)
        self.assertEqual(result.admitted_badges, (OBSERVED,))
        self.assertIn("VERIFIER_CONFIGURATION", codes(result))

    def test_verifier_finding_surrogate_is_contained(self) -> None:
        artifact = make_artifact()
        result = intake(
            artifact,
            verifier_results={
                "artifact_sha256": artifact["artifact_sha256"],
                "checks": [],
                "negative_controls": [],
                "findings": ["\ud800"],
            },
        )
        self.assertFalse(result.verification_valid)
        self.assertIn("VERIFIER_FINDINGS", codes(result))
        self.assertEqual(result.admitted_badges, (OBSERVED,))


if __name__ == "__main__":
    unittest.main()
