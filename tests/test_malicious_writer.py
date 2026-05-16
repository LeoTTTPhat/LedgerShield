import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from common import Event, generate_synthetic_events
from malicious_writer import (
    PolicySigner,
    QuorumWitness,
    audit_completeness,
    make_conflicting_checkpoint,
    verify_policy_checkpoint,
    verify_quorum,
)
from merkle_signed_log import KeyRegistry, MerkleSignedLog


class TestMaliciousWriterExtension(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="malicious_writer_")
        self.key_dir = os.path.join(self.tmp, "keys")
        self.registry_path = os.path.join(self.tmp, "registry.json")
        self.registry = KeyRegistry.init_or_load(self.registry_path, self.key_dir)
        self.private_path = os.path.join(self.key_dir, f"{self.registry.active_key_id}_private.pem")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_policy_signer_enforces_sequence_and_tree_monotonicity(self) -> None:
        signer = PolicySigner(
            self.private_path,
            self.registry.active_key_id,
            os.path.join(self.tmp, "policy_state.json"),
        )
        old_commitment = MerkleSignedLog.commit(generate_synthetic_events(8, 1), self.private_path, self.registry.active_key_id)
        c1 = MerkleSignedLog.commit(generate_synthetic_events(10, 1), self.private_path, self.registry.active_key_id)
        c2 = MerkleSignedLog.commit(generate_synthetic_events(12, 1), self.private_path, self.registry.active_key_id)

        p1 = signer.sign(c1)
        p2 = signer.sign(c2)
        self.assertEqual(p1.sequence, 1)
        self.assertEqual(p2.sequence, 2)
        self.assertTrue(verify_policy_checkpoint(p1, self.registry))
        self.assertTrue(verify_policy_checkpoint(p2, self.registry))

        with self.assertRaises(ValueError):
            signer.sign(c2, sequence=2)
        with self.assertRaises(ValueError):
            signer.sign(old_commitment)

    def test_quorum_accepts_threshold_and_rejects_conflicts(self) -> None:
        signer = PolicySigner(
            self.private_path,
            self.registry.active_key_id,
            os.path.join(self.tmp, "policy_state.json"),
        )
        commitment = MerkleSignedLog.commit(generate_synthetic_events(16, 3), self.private_path, self.registry.active_key_id)
        checkpoint = signer.sign(commitment)
        witnesses = [
            QuorumWitness.create(f"w{i}", os.path.join(self.tmp, "witness_keys"), os.path.join(self.tmp, "witness_state"))
            for i in range(3)
        ]
        certs = [w.sign_checkpoint(checkpoint) for w in witnesses[:2]]
        pubkeys = {w.witness_id: w.public_key_path for w in witnesses}

        self.assertTrue(verify_quorum(checkpoint, certs, pubkeys, threshold=2))
        self.assertFalse(verify_quorum(checkpoint, certs[:1], pubkeys, threshold=2))
        self.assertFalse(verify_quorum(checkpoint, [certs[0], certs[0]], pubkeys, threshold=2))

        conflicting = make_conflicting_checkpoint(checkpoint, "f" * 64)
        with self.assertRaises(ValueError):
            witnesses[0].sign_checkpoint(conflicting)

    def test_completeness_source_audit_detects_missing_and_duplicate_ids(self) -> None:
        events = [
            Event(i, 1700000000 + i, f"ACC-{i}", "1.00", "USD", "TRANSFER", f"source={i}")
            for i in range(1, 6)
        ]
        expected = [str(i) for i in range(1, 6)]

        omitted = [event for event in events if event.event_id != 3]
        omission_report = audit_completeness(omitted, expected)
        self.assertFalse(omission_report["complete"])
        self.assertEqual(omission_report["missing_ids"], ["3"])

        duplicated = events + [events[-1]]
        duplicate_report = audit_completeness(duplicated, expected)
        self.assertFalse(duplicate_report["complete"])
        self.assertEqual(duplicate_report["duplicate_ids"], ["5"])

        complete_report = audit_completeness(events, expected)
        self.assertTrue(complete_report["complete"])


if __name__ == "__main__":
    unittest.main()
