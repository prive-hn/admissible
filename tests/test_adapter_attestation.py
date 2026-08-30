"""Authenticated execution-adapter receipts.

The kernel still records executed identity through Observe. These tests pin
the layer that makes that report independent of the worker: a gateway key
signs attempt/nonce, model revision, and provider request id, and replay of
those bindings fails closed.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from fcd.core import Enforcer, Policy
from fcd.head import HMACSHA256Keyring, HMACSHA256Signer


def policy() -> Policy:
    return Policy(
        allow={"impl": {"alice"}},
        deny={"impl": set()},
        phi={"alice": "vendorA:model-a"},
        required={"impl": [("write", "w1")]},
    )


def observation(**overrides):
    from fcd.adapter_attestation import ProviderObservation
    base = dict(
        executor_id="gateway",
        run_id="run-1",
        package_hash_observed="a" * 64,
        continuation_hash="b" * 64,
        executed_provider="vendorA",
        executed_model="model-a",
        model_revision="deploy-9",
        provider_request_id="req-1",
    )
    base.update(overrides)
    return ProviderObservation(**base)


def envelope():
    return {
        "attempt_id": "att-1",
        "nonce": "nonce-1",
        "issued_at": 10,
    }


class AdapterAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = HMACSHA256Signer("gateway-1", b"g" * 32)
        self.keyring = HMACSHA256Keyring({"gateway-1": b"g" * 32})
        from fcd.adapter_attestation import AdapterReplayLog
        self.replay = AdapterReplayLog()

    def issue(self, **overrides):
        from fcd.adapter_attestation import issue_adapter_receipt
        env = envelope()
        env.update({k: overrides.pop(k) for k in list(overrides) if k in env})
        obs = observation(**overrides)
        return issue_adapter_receipt(
            attempt_id=env["attempt_id"],
            nonce=env["nonce"],
            observation=obs,
            signer=self.signer,
            issued_at=env["issued_at"],
        )

    def test_gateway_issues_a_signed_receipt_bound_to_attempt_and_nonce(self) -> None:
        from fcd.adapter_attestation import verify_adapter_receipt
        receipt = self.issue()
        self.assertEqual(receipt.attempt_id, "att-1")
        self.assertEqual(receipt.nonce, "nonce-1")
        self.assertEqual(receipt.model_revision, "deploy-9")
        self.assertEqual(receipt.provider_request_id, "req-1")
        self.assertEqual(receipt.identity_kind, "attested")
        self.assertTrue(verify_adapter_receipt(
            receipt, self.keyring, self.replay,
            attempt_id="att-1", nonce="nonce-1",
            package_hash_observed="a" * 64,
            continuation_hash="b" * 64,
        ))

    def test_worker_cannot_forge_executed_model_without_the_gateway_key(self) -> None:
        from fcd.adapter_attestation import (
            AdapterReplayLog,
            AdapterVerificationError,
            verify_adapter_receipt,
        )
        receipt = self.issue()
        forged = receipt.__class__(**{
            **{f.name: getattr(receipt, f.name)
               for f in receipt.__dataclass_fields__.values()},
            "executed_model": "model-secret",
        })
        with self.assertRaises(AdapterVerificationError):
            verify_adapter_receipt(
                forged, self.keyring, AdapterReplayLog(),
                attempt_id="att-1", nonce="nonce-1",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

        wrong = HMACSHA256Keyring({"gateway-1": b"x" * 32})
        with self.assertRaises(AdapterVerificationError):
            verify_adapter_receipt(
                receipt, wrong, AdapterReplayLog(),
                attempt_id="att-1", nonce="nonce-1",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

    def test_replay_of_attempt_nonce_or_provider_request_id_fails_closed(self) -> None:
        from fcd.adapter_attestation import (
            AdapterReplayError,
            verify_adapter_receipt,
        )
        receipt = self.issue()
        self.assertTrue(verify_adapter_receipt(
            receipt, self.keyring, self.replay,
            attempt_id="att-1", nonce="nonce-1",
            package_hash_observed="a" * 64,
            continuation_hash="b" * 64,
        ))
        with self.assertRaises(AdapterReplayError):
            verify_adapter_receipt(
                receipt, self.keyring, self.replay,
                attempt_id="att-1", nonce="nonce-1",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

        other_attempt = self.issue(attempt_id="att-2", nonce="nonce-2")
        with self.assertRaises(AdapterReplayError):
            verify_adapter_receipt(
                other_attempt, self.keyring, self.replay,
                attempt_id="att-2", nonce="nonce-2",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

    def test_missing_revision_or_provider_request_id_is_refused(self) -> None:
        from fcd.adapter_attestation import AdapterIssueError
        with self.assertRaises(AdapterIssueError):
            self.issue(model_revision="")
        with self.assertRaises(AdapterIssueError):
            self.issue(provider_request_id="")

    def test_unsigned_observation_is_route_identity_not_attested(self) -> None:
        from fcd.adapter_attestation import route_identity
        labeled = route_identity(observation())
        self.assertEqual(labeled.identity_kind, "route")
        self.assertEqual(labeled.executed_model, "model-a")
        self.assertEqual(labeled.signature, "")
        self.assertEqual(labeled.key_id, "")

    def test_observe_from_verified_receipt_writes_signed_executed_model(self) -> None:
        from fcd.adapter_attestation import observe_attested
        e = Enforcer(policy())
        e.open("w", "impl", "hash1")
        e.admit("w", "alice")
        e.bind("w", True)
        receipt = self.issue()
        observe_attested(
            e, "w", receipt, self.keyring, self.replay,
            package_hash_observed="a" * 64,
            continuation_hash="b" * 64,
            attempt_id="att-1",
            nonce="nonce-1",
        )
        st = e.items["w"].stages[0]
        self.assertEqual(st.m_exec, "vendorA:model-a")
        e.decide_pass("w")
        self.assertEqual(st.pc, "Passed")

    def test_observe_attested_refuses_a_mismatched_attempt_binding(self) -> None:
        from fcd.adapter_attestation import (
            AdapterReplayLog,
            AdapterVerificationError,
            observe_attested,
        )
        e = Enforcer(policy())
        e.open("w", "impl", "hash1")
        e.admit("w", "alice")
        e.bind("w", True)
        receipt = self.issue()
        with self.assertRaises(AdapterVerificationError):
            observe_attested(
                e, "w", receipt, self.keyring, AdapterReplayLog(),
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
                attempt_id="att-OTHER",
                nonce="nonce-1",
            )
        self.assertIsNone(e.items["w"].stages[0].m_exec)

    def test_observe_attested_requires_caller_attempt_and_nonce(self) -> None:
        from fcd.adapter_attestation import observe_attested
        e = Enforcer(policy())
        e.open("w", "impl", "hash1")
        e.admit("w", "alice")
        e.bind("w", True)
        receipt = self.issue()
        with self.assertRaises(TypeError):
            observe_attested(
                e, "w", receipt, self.keyring, self.replay,
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

    def test_replay_log_rejects_reused_attempt_id_or_nonce_alone(self) -> None:
        from fcd.adapter_attestation import (
            AdapterReplayError,
            AdapterReplayLog,
            verify_adapter_receipt,
        )
        first = self.issue()
        replay = AdapterReplayLog()
        self.assertTrue(verify_adapter_receipt(
            first, self.keyring, replay,
            attempt_id="att-1", nonce="nonce-1",
            package_hash_observed="a" * 64,
            continuation_hash="b" * 64,
        ))
        same_attempt = self.issue(
            attempt_id="att-1", nonce="nonce-other", provider_request_id="req-other")
        with self.assertRaises(AdapterReplayError):
            verify_adapter_receipt(
                same_attempt, self.keyring, replay,
                attempt_id="att-1", nonce="nonce-other",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )
        same_nonce = self.issue(
            attempt_id="att-other", nonce="nonce-1", provider_request_id="req-third")
        with self.assertRaises(AdapterReplayError):
            verify_adapter_receipt(
                same_nonce, self.keyring, replay,
                attempt_id="att-other", nonce="nonce-1",
                package_hash_observed="a" * 64,
                continuation_hash="b" * 64,
            )

    def test_transport_cannot_supply_the_signature(self) -> None:
        from fcd.adapter_attestation import AttestingGateway, ProviderObservation
        transport_obs = ProviderObservation(
            executor_id="worker",
            run_id="run-9",
            package_hash_observed="a" * 64,
            continuation_hash="b" * 64,
            executed_provider="vendorA",
            executed_model="model-a",
            model_revision="deploy-9",
            provider_request_id="req-9",
        )

        def transport(_request):
            return transport_obs

        gateway = AttestingGateway(transport, self.signer)
        receipt = gateway.run(
            attempt_id="att-1", nonce="nonce-1", issued_at=10, request=None)
        self.assertEqual(receipt.key_id, "gateway-1")
        self.assertEqual(receipt.executor_id, "gateway-1")
        self.assertNotEqual(receipt.signature, "")
        self.assertEqual(receipt.provider_request_id, "req-9")


class InferenceGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = HMACSHA256Signer("gateway-1", b"g" * 32)
        self.keyring = HMACSHA256Keyring({"gateway-1": b"g" * 32})

    def test_workers_do_not_possess_provider_credentials(self) -> None:
        from fcd.adapter_attestation import (
            AdapterIssueError,
            InferenceGateway,
            ProviderCredentials,
        )
        creds = ProviderCredentials(provider="vendorA", secret=b"sk-live")
        seen = {"worker": None, "provider": None}

        def provider_call(credentials, request):
            seen["provider"] = credentials.secret
            return observation(provider_request_id="req-g", audit_ref="bill-1")

        def worker(request):
            seen["worker"] = request
            raise AssertionError("worker must not call the provider")

        gateway = InferenceGateway(
            signer=self.signer, credentials=creds, provider_call=provider_call)
        with self.assertRaises(AdapterIssueError):
            gateway.export_credentials()
        receipt = gateway.infer(
            attempt_id="att-1", nonce="nonce-1", issued_at=10, request={"op": "run"})
        self.assertEqual(seen["provider"], b"sk-live")
        self.assertIsNone(seen["worker"])
        self.assertEqual(receipt.identity_kind, "attested")
        self.assertEqual(receipt.audit_ref, "bill-1")
        self.assertNotIn(b"sk-live", repr(gateway).encode())

    def test_unattested_provider_fails_closed_when_attestation_is_required(self) -> None:
        from fcd.adapter_attestation import (
            AdapterVerificationError,
            ExecutionFence,
            route_identity,
        )
        fence = ExecutionFence(require_attested=True)
        labeled = route_identity(observation())
        with self.assertRaises(AdapterVerificationError):
            fence.accept(labeled)
        fence_open = ExecutionFence(require_attested=False)
        accepted = fence_open.accept(labeled)
        self.assertEqual(accepted.identity_kind, "route")

    def test_credentials_are_not_copyable_or_serializable(self) -> None:
        import copy
        import pickle
        from fcd.adapter_attestation import ProviderCredentials
        creds = ProviderCredentials(provider="vendorA", secret=b"sk-live")
        with self.assertRaises(TypeError):
            copy.copy(creds)
        with self.assertRaises(TypeError):
            pickle.dumps(creds)


if __name__ == "__main__":
    unittest.main()
