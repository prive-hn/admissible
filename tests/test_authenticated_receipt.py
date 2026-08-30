"""Authenticated, kernel-issued Admissible composition receipts."""
from __future__ import annotations

import dataclasses
import copy
import json
import os
import pickle
import sys
import threading
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from test_rga_calibration import CalHarness  # noqa: E402
from protocol import schema_path  # noqa: E402

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - stdlib-only install
    HAVE_JSONSCHEMA = False


def receipt_api():
    try:
        from fcd.head import (  # type: ignore[attr-defined]
            HMACSHA256Keyring,
            HMACSHA256Signer,
            HeadVerificationError,
            MonotoneHeadRegistry,
            compute_journal_head,
            make_receipt,
            verify_current,
        )
        from rga.attestation import (  # type: ignore[attr-defined]
            ReceiptIssueError,
            ReceiptVerificationError,
            admissibility_receipt_from_dict,
            admissibility_receipt_to_dict,
            issue_admissibility_receipt,
            verify_admissibility_receipt,
        )
    except ImportError:
        return None
    return {
        "HMACSHA256Keyring": HMACSHA256Keyring,
        "HMACSHA256Signer": HMACSHA256Signer,
        "HeadVerificationError": HeadVerificationError,
        "MonotoneHeadRegistry": MonotoneHeadRegistry,
        "compute_head": compute_journal_head,
        "make_head_receipt": make_receipt,
        "verify_current": verify_current,
        "ReceiptVerificationError": ReceiptVerificationError,
        "ReceiptIssueError": ReceiptIssueError,
        "from_dict": admissibility_receipt_from_dict,
        "to_dict": admissibility_receipt_to_dict,
        "issue": issue_admissibility_receipt,
        "verify": verify_admissibility_receipt,
    }


def sealed_harness():
    h = CalHarness()
    h.declare_tests()
    h.seal_line()
    return h


class AuthenticatedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.api = receipt_api()
        self.assertIsNotNone(self.api, "authenticated receipt API is missing")
        self.signer = self.api["HMACSHA256Signer"]("issuer-1", b"a" * 32)
        self.registry = self.api["MonotoneHeadRegistry"]()

    def issue(self, h, at=10):
        return self.api["issue"](
            "w", h.e, h.a, h.cal, self.registry, self.signer,
            journal_namespace="test-stack", issued_at=at)

    def test_kernel_issues_and_verifies_a_positive_composed_receipt(self):
        import fcd
        import rga
        h = sealed_harness()
        receipt = self.issue(h)

        self.assertEqual(receipt.base_version, fcd.__version__)
        for package, names in (
            (fcd, ("JournalEvent", "HMACSHA256Signer", "MonotoneHeadRegistry")),
            (rga, ("AdmissibilityReceipt", "issue_admissibility_receipt",
                   "verify_admissibility_receipt")),
        ):
            for name in names:
                self.assertTrue(hasattr(package, name), name)
        self.assertTrue(receipt.sealed)
        self.assertTrue(receipt.mediated)
        self.assertFalse(receipt.tainted)
        self.assertFalse(receipt.impeached)
        self.assertTrue(receipt.predicates_ok())
        self.assertEqual(receipt.artifact_hash, h.a.sealed["w"].artifact_hash)
        self.assertEqual(
            [receipt.fcd_head.journal_id, receipt.rga_head.journal_id,
             receipt.calibration_head.journal_id],
            ["admissible/test-stack/fcd", "admissible/test-stack/rga",
             "admissible/test-stack/calibration"],
        )
        self.assertEqual(receipt.fcd_head.event_count, len(h.e.events))
        self.assertEqual(receipt.rga_head.event_count, len(h.a.events))
        self.assertEqual(receipt.calibration_head.event_count, len(h.cal.events))
        self.assertTrue(self.api["verify"](
            receipt, h.e, h.a, h.cal, self.registry, self.signer))

    def test_receipt_has_a_closed_json_roundtrip(self):
        h = sealed_harness()
        receipt = self.issue(h)
        plain = self.api["to_dict"](receipt)
        rebuilt = self.api["from_dict"](
            json.loads(json.dumps(plain, sort_keys=True)))
        self.assertEqual(rebuilt, receipt)
        with self.assertRaises(ValueError):
            self.api["from_dict"]({**plain, "unmodelled": True})
        with self.assertRaises(ValueError):
            self.api["from_dict"]({**plain, "sealed": False})
        with self.assertRaises(ValueError):
            self.api["from_dict"]({**plain, "journal_namespace": "other-stack"})

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_receipt_and_head_match_closed_protocol_schemas(self):
        h = sealed_harness()
        receipt = self.issue(h)
        plain = self.api["to_dict"](receipt)
        receipt_schema = json.loads(
            schema_path("admissibility-receipt.schema.json").read_text())
        head_schema = json.loads(
            schema_path("head-receipt.schema.json").read_text())
        Draft202012Validator.check_schema(receipt_schema)
        Draft202012Validator.check_schema(head_schema)
        self.assertTrue(Draft202012Validator(receipt_schema).is_valid(plain))
        self.assertTrue(Draft202012Validator(head_schema).is_valid(plain["fcd_head"]))
        self.assertFalse(Draft202012Validator(receipt_schema).is_valid(
            {**plain, "sealed": "yes"}))
        wrong_head = json.loads(json.dumps(plain))
        wrong_head["fcd_head"]["journal_id"] = "admissible/rga"
        self.assertFalse(Draft202012Validator(receipt_schema).is_valid(wrong_head))

    def test_public_field_rehash_cannot_replace_issuer_authentication(self):
        h = sealed_harness()
        receipt = self.issue(h)
        tampered = dataclasses.replace(receipt, tainted=True)
        with self.assertRaises(self.api["ReceiptVerificationError"]):
            self.api["verify"](
                tampered, h.e, h.a, h.cal, self.registry, self.signer)

        wrong = self.api["HMACSHA256Keyring"]({"issuer-1": b"b" * 32})
        with self.assertRaises(self.api["ReceiptVerificationError"]):
            self.api["verify"](
                receipt, h.e, h.a, h.cal, self.registry, wrong)

    def test_stale_receipt_fails_and_reissue_carries_impeachment(self):
        h = sealed_harness()
        old = self.issue(h, at=10)
        h.tier_a_escape()

        with self.assertRaises(self.api["ReceiptVerificationError"]) as caught:
            self.api["verify"](
                old, h.e, h.a, h.cal, self.registry, self.signer)
        self.assertEqual(str(caught.exception),
                         "receipt does not describe current kernel state")

        current = self.issue(h, at=11)
        self.assertTrue(current.impeached)
        self.assertFalse(current.predicates_ok())
        self.assertNotEqual(current.receipt_hash, old.receipt_hash)
        self.assertTrue(self.api["verify"](
            current, h.e, h.a, h.cal, self.registry, self.signer))

    def test_registry_current_rejects_coherent_tail_truncation(self):
        h = sealed_harness()
        receipt = self.issue(h)
        truncated = tuple(h.cal.events[:-1])
        with self.assertRaises(self.api["HeadVerificationError"]):
            self.api["verify_current"](
                receipt.calibration_head.journal_id, truncated,
                receipt.calibration_head,
                self.registry, self.signer)

    def test_authenticated_head_rejects_a_coherent_root_input_rewrite(self):
        from fcd.core import Enforcer
        from fcd.journal import to_plain_json
        from test_journal_hardening import policy

        enforcer = Enforcer(policy())
        enforcer.open("w", "impl", "original-body")
        head = self.api["compute_head"]("rewrite-test", enforcer.events)
        receipt = self.api["make_head_receipt"](head, "", 1, self.signer)
        self.registry.accept(receipt, self.signer)

        rewritten = [to_plain_json(event) for event in enforcer.events]
        rewritten[0]["body_hash"] = "coherently-rewritten-body"
        rebuilt = Enforcer.from_events(rewritten, policy())
        self.assertEqual(rebuilt.items["w"].body, "coherently-rewritten-body")
        with self.assertRaises(self.api["HeadVerificationError"]):
            self.api["verify_current"](
                "rewrite-test", rebuilt.events, receipt,
                self.registry, self.signer)

    def test_cross_wired_authorities_refuse_before_registry_mutation(self):
        h1 = sealed_harness()
        h2 = sealed_harness()
        with self.assertRaises(ValueError) as caught:
            self.api["issue"](
                "w", h1.e, h1.a, h2.cal, self.registry, self.signer,
                journal_namespace="test-stack", issued_at=10)
        self.assertEqual(str(caught.exception),
                         "admissibility receipt requires one composed authority stack")
        for journal_id in ("admissible/test-stack/fcd",
                           "admissible/test-stack/rga",
                           "admissible/test-stack/calibration"):
            self.assertIsNone(self.registry.current(journal_id))

    def test_head_batch_acceptance_is_atomic(self):
        head_a = self.api["compute_head"]("a", ({"type": "a"},))
        head_b = self.api["compute_head"]("b", ({"type": "b"},))
        receipt_a = self.api["make_head_receipt"](
            head_a, "", 1, self.signer)
        receipt_b = self.api["make_head_receipt"](
            head_b, "", 1, self.signer)
        hostile_b = dataclasses.replace(receipt_b, signature="0" * 64)
        with self.assertRaises(ValueError):
            self.registry.accept_batch((receipt_a, hostile_b), self.signer)
        self.assertIsNone(self.registry.current("a"))
        self.assertIsNone(self.registry.current("b"))

    def test_concurrent_independent_stacks_cannot_lose_an_accepted_head(self):
        heads = tuple(
            self.api["compute_head"](journal_id, ({"type": journal_id},))
            for journal_id in ("stack-a", "stack-b"))
        receipts = tuple(
            self.api["make_head_receipt"](head, "", 1, self.signer)
            for head in heads)
        barrier = threading.Barrier(2)
        base = self.signer

        class BarrierVerifier:
            def verify_signature(inner, *args):
                barrier.wait(timeout=5)
                return base.verify_signature(*args)

        errors = []

        def accept(receipt):
            try:
                self.registry.accept(receipt, BarrierVerifier())
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = tuple(threading.Thread(target=accept, args=(receipt,))
                        for receipt in receipts)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(
            [self.registry.current(head.journal_id) for head in heads],
            list(receipts))

    def test_make_receipt_refuses_invalid_chain_and_time_before_signing(self):
        head = self.api["compute_head"]("structural", ({"type": "a"},))
        malformed = dataclasses.replace(head, head_digest="0" * 64)
        with self.assertRaises(ValueError):
            self.api["make_head_receipt"](malformed, "", 1, self.signer)

        first = self.api["make_head_receipt"](head, "", 10, self.signer)
        successor = self.api["compute_head"](
            "structural", ({"type": "a"}, {"type": "b"}))
        with self.assertRaises(ValueError):
            self.api["make_head_receipt"](
                successor, first.receipt_hash, 9, self.signer,
                previous=first)

        tampered_previous = dataclasses.replace(first, issued_at=0)
        calls = []
        base = self.signer

        class CountingSigner:
            algorithm = base.algorithm
            key_id = base.key_id

            def sign(inner, payload):
                calls.append(payload)
                return base.sign(payload)

        with self.assertRaises(ValueError):
            self.api["make_head_receipt"](
                successor, first.receipt_hash, 9, CountingSigner(),
                previous=tampered_previous)
        self.assertEqual(calls, [])

    def test_duplicate_accept_cannot_create_a_signed_unreplayable_successor(self):
        from fcd.core import Enforcer, Policy

        h = sealed_harness()
        first = self.issue(h, at=10)
        before = h.e.events
        with self.assertRaises(ValueError):
            h.e.accept("w")
        self.assertEqual(h.e.events, before)
        rebuilt = Enforcer.from_events(h.e.events, h.e.policy)
        self.assertEqual(rebuilt.events, h.e.events)
        current = self.issue(h, at=11)
        self.assertEqual(current.fcd_head, first.fcd_head)
        self.assertTrue(self.api["verify"](
            current, h.e, h.a, h.cal, self.registry, self.signer))

        zero_policy = Policy(
            allow={"empty": set()}, deny={"empty": set()}, phi={},
            required={"empty": []}, version="zero")
        zero = Enforcer(zero_policy)
        zero.open("empty", "empty", "body")
        zero.accept("empty")
        zero_rebuilt = Enforcer.from_events(zero.events, zero_policy)
        self.assertEqual(zero_rebuilt.events, zero.events)
        self.assertIn("empty", zero_rebuilt.store)

    def test_successor_head_requires_a_verifiable_prefix_extension(self):
        first_head = self.api["compute_head"](
            "prefix-test", ({"type": "a"}, {"type": "b"}))
        first = self.api["make_head_receipt"](
            first_head, "", 1, self.signer)
        self.registry.accept(first, self.signer)

        honest_head = self.api["compute_head"](
            "prefix-test",
            ({"type": "a"}, {"type": "b"}, {"type": "c"}))
        honest = self.api["make_head_receipt"](
            honest_head, first.receipt_hash, 2, self.signer,
            previous=first)
        self.registry.accept(honest, self.signer)
        self.assertEqual(honest.extension_digests,
                         (honest_head.event_digests[-1],))

        fork_head = self.api["compute_head"](
            "prefix-test",
            ({"type": "a"}, {"type": "fork"},
             {"type": "d"}, {"type": "e"}))
        with self.assertRaises(ValueError):
            self.api["make_head_receipt"](
                fork_head, honest.receipt_hash, 3, self.signer,
                previous=honest)

        # Even a validly signed hand-built successor cannot bypass the registry's
        # independent extension proof.
        from fcd.head import HeadReceipt, _digest, _unsigned_head_payload
        extension = fork_head.event_digests[honest.event_count:]
        unsigned = _unsigned_head_payload(
            fork_head.journal_id, fork_head.event_count, fork_head.head_digest,
            honest.receipt_hash, extension, 3,
            self.signer.algorithm, self.signer.key_id)
        signature = self.signer.sign(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode())
        malicious = HeadReceipt(
            journal_id=fork_head.journal_id,
            event_count=fork_head.event_count,
            head_digest=fork_head.head_digest,
            previous_receipt_hash=honest.receipt_hash,
            extension_digests=extension,
            issued_at=3,
            algorithm=self.signer.algorithm,
            key_id=self.signer.key_id,
            signature=signature,
            receipt_hash=_digest(dict(unsigned, signature=signature)),
        )
        with self.assertRaises(ValueError):
            self.registry.accept(malicious, self.signer)

    def test_secret_holders_refuse_copy_and_serialization(self):
        keyring = self.api["HMACSHA256Keyring"]({"issuer-1": b"a" * 32})
        for holder in (self.signer, keyring):
            for operation in (
                lambda value: copy.copy(value),
                lambda value: copy.deepcopy(value),
                lambda value: pickle.dumps(value),
            ):
                with self.subTest(holder=type(holder).__name__, operation=operation):
                    with self.assertRaises(TypeError):
                        operation(holder)

    def test_head_signature_payload_is_domain_separated(self):
        seen = []
        base = self.signer

        class RecordingSigner:
            algorithm = base.algorithm
            key_id = base.key_id

            def sign(self, payload):
                seen.append(json.loads(payload))
                return base.sign(payload)

            def verify_signature(self, *args):
                return base.verify_signature(*args)

        head = self.api["compute_head"]("domain-test", ({"type": "x"},))
        self.api["make_head_receipt"](head, "", 1, RecordingSigner())
        # Pinned to the kernel version, not the product package version: this
        # string is inside every head signature, so moving it invalidates every
        # head receipt already issued.
        import fcd

        self.assertEqual(seen[0]["domain"], "admissible/v0.5/journal-head")
        self.assertTrue(
            seen[0]["domain"].startswith(
                "admissible/v" + ".".join(fcd.__version__.split(".")[:2]) + "/"),
            f"{seen[0]['domain']} does not track fcd {fcd.__version__}")

    def test_issue_refuses_if_the_kernel_moves_while_signing(self):
        h = sealed_harness()
        base = self.signer

        class MutatingSigner:
            algorithm = base.algorithm
            key_id = base.key_id

            def __init__(self):
                self.calls = 0

            def sign(inner, payload):
                inner.calls += 1
                if inner.calls == 4:  # three heads, then the composed receipt
                    from fcd.journal import JournalEvent
                    h.cal._events.append(JournalEvent({"type": "cal_race", "ts": 10}))
                return base.sign(payload)

            def verify_signature(inner, *args):
                return base.verify_signature(*args)

        with self.assertRaises(self.api["ReceiptIssueError"]) as caught:
            self.api["issue"](
                "w", h.e, h.a, h.cal, self.registry, MutatingSigner(),
                journal_namespace="test-stack", issued_at=10)
        self.assertEqual(str(caught.exception),
                         "kernel changed while issuing admissibility receipt")
        for journal_id in ("admissible/test-stack/fcd",
                           "admissible/test-stack/rga",
                           "admissible/test-stack/calibration"):
            self.assertIsNone(self.registry.current(journal_id))

    def test_receipt_for_unsealed_subject_is_authenticated_negative_evidence(self):
        h = CalHarness()
        h.declare_tests()
        receipt = self.issue(h)
        self.assertFalse(receipt.sealed)
        self.assertFalse(receipt.mediated)
        self.assertFalse(receipt.predicates_ok())
        self.assertEqual(receipt.artifact_hash, "")
        self.assertTrue(self.api["verify"](
            receipt, h.e, h.a, h.cal, self.registry, self.signer))

    def test_unrelated_stacks_use_independent_registry_namespaces(self):
        first = sealed_harness()
        second = sealed_harness()
        receipt_a = self.api["issue"](
            "w", first.e, first.a, first.cal, self.registry, self.signer,
            journal_namespace="stack-a", issued_at=1)
        receipt_b = self.api["issue"](
            "w", second.e, second.a, second.cal, self.registry, self.signer,
            journal_namespace="stack-b", issued_at=1)
        self.assertEqual(receipt_a.journal_namespace, "stack-a")
        self.assertEqual(receipt_b.journal_namespace, "stack-b")
        self.assertNotEqual(receipt_a.fcd_head.journal_id,
                            receipt_b.fcd_head.journal_id)
        self.assertTrue(self.api["verify"](
            receipt_a, first.e, first.a, first.cal,
            self.registry, self.signer))
        self.assertTrue(self.api["verify"](
            receipt_b, second.e, second.a, second.cal,
            self.registry, self.signer))


if __name__ == "__main__":
    unittest.main()
