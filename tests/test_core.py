import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from attacks import AttackSuite
from baseline_sqlite import SQLiteAuditBaseline
from common import Event, generate_events, generate_synthetic_events, read_events_jsonl
from merkle_signed_log import KeyRegistry, MerkleCommitment, MerkleSignedLog, _event_leaf
from witness_anchor import WitnessAnchorLog


class TestCore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="auditlog_test_")
        self.key_dir = os.path.join(self.tmp, "keys")
        self.registry_path = os.path.join(self.tmp, "registry.json")
        self.registry = KeyRegistry.init_or_load(self.registry_path, self.key_dir)
        self.private_path = os.path.join(self.key_dir, f"{self.registry.active_key_id}_private.pem")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_deterministic_generation(self) -> None:
        a = generate_synthetic_events(20, 7)
        b = generate_synthetic_events(20, 7)
        self.assertEqual([x.canonical_json() for x in a], [x.canonical_json() for x in b])

    def test_calibrated_generation_is_deterministic_and_varied(self) -> None:
        a = generate_events(50, 11, "calibrated")
        b = generate_events(50, 11, "calibrated")
        self.assertEqual([x.canonical_json() for x in a], [x.canonical_json() for x in b])
        self.assertGreater(len({x.event_type for x in a}), 1)
        self.assertTrue(any(x.reference.startswith("CAL-11-") for x in a))

    def test_read_events_jsonl_roundtrip(self) -> None:
        events = generate_synthetic_events(3, 5)
        path = os.path.join(self.tmp, "events.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for event in events:
                f.write(event.canonical_json() + "\n")
        loaded = read_events_jsonl(path)
        self.assertEqual([x.canonical_json() for x in events], [x.canonical_json() for x in loaded])

    def test_canonicalization_test_vector(self) -> None:
        event = Event(
            event_id=1,
            timestamp=1700000042,
            account_id="ACC-12345",
            amount="123.45",
            currency="USD",
            event_type="DEPOSIT",
            reference="REF-000001",
        )
        self.assertEqual(
            event.canonical_json(),
            '{"account_id":"ACC-12345","amount":"123.45","currency":"USD","event_id":1,'
            '"event_type":"DEPOSIT","reference":"REF-000001","timestamp":1700000042}',
        )
        self.assertEqual(
            _event_leaf(event),
            "cc2645db6663c3a3a6516b83d0c89ae1d34629dcd0a4a85601b3c04e174befbd",
        )

    def test_signature_negative_on_tamper(self) -> None:
        events = generate_synthetic_events(30, 42)
        commitment = MerkleSignedLog.commit(events, self.private_path, self.registry.active_key_id)
        ok, _ = MerkleSignedLog.verify(events, commitment, self.registry)
        self.assertTrue(ok)
        tampered = AttackSuite.modify(events, 42)
        ok_tampered, _ = MerkleSignedLog.verify(tampered, commitment, self.registry)
        self.assertFalse(ok_tampered)

    def test_commitment_signature_binds_metadata(self) -> None:
        events = generate_synthetic_events(30, 42)
        commitment = MerkleSignedLog.commit(events, self.private_path, self.registry.active_key_id)
        altered_key = MerkleCommitment(
            root_hash=commitment.root_hash,
            signature_hex=commitment.signature_hex,
            key_id="missing-key",
            tree_size=commitment.tree_size,
        )
        altered_size = MerkleCommitment(
            root_hash=commitment.root_hash,
            signature_hex=commitment.signature_hex,
            key_id=commitment.key_id,
            tree_size=commitment.tree_size + 1,
        )
        self.assertFalse(MerkleSignedLog.verify(events, altered_key, self.registry)[0])
        self.assertFalse(MerkleSignedLog.verify(events, altered_size, self.registry)[0])

    def test_inclusion_proof(self) -> None:
        events = generate_synthetic_events(40, 5)
        commitment = MerkleSignedLog.commit(events, self.private_path, self.registry.active_key_id)
        proof = MerkleSignedLog.gen_inclusion_proof(events, 3)
        self.assertTrue(MerkleSignedLog.verify_inclusion_proof(events[3], 3, proof, commitment.root_hash))
        self.assertFalse(MerkleSignedLog.verify_inclusion_proof(events[4], 3, proof, commitment.root_hash))

    def test_consistency_proof(self) -> None:
        old_events = generate_synthetic_events(20, 3)
        new_events = old_events + generate_synthetic_events(5, 4)
        proof = MerkleSignedLog.gen_consistency_proof(old_events, new_events)
        self.assertIn("proof_hashes", proof)
        self.assertLess(len(proof["proof_hashes"]), len(old_events))
        self.assertTrue(MerkleSignedLog.verify_consistency_proof(proof, new_events))
        self.assertTrue(MerkleSignedLog.verify_consistency_proof_external(proof))
        broken = new_events[:]
        broken[0] = AttackSuite.modify([broken[0]], 9)[0]
        self.assertFalse(MerkleSignedLog.verify_consistency_proof(proof, broken))
        malformed = dict(proof)
        malformed["proof_hashes"] = proof["proof_hashes"][:-1]
        self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(malformed))
        forged = dict(proof)
        forged_hashes = list(proof["proof_hashes"])
        forged_hashes[0] = "00" * 32
        forged["proof_hashes"] = forged_hashes
        self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(forged))

    def test_key_rotation_and_revocation(self) -> None:
        events = generate_synthetic_events(10, 33)
        c1 = MerkleSignedLog.commit(events, self.private_path, self.registry.active_key_id)
        ok1, _ = MerkleSignedLog.verify(events, c1, self.registry)
        self.assertTrue(ok1)

        self.registry.rotate_key(self.registry_path, self.key_dir)
        new_private_path = os.path.join(self.key_dir, f"{self.registry.active_key_id}_private.pem")
        c2 = MerkleSignedLog.commit(events, new_private_path, self.registry.active_key_id)
        ok2, _ = MerkleSignedLog.verify(events, c2, self.registry)
        self.assertTrue(ok2)

        self.registry.revoke_key(c2.key_id, self.registry_path)
        self.registry = KeyRegistry.init_or_load(self.registry_path, self.key_dir)
        ok2_revoked, _ = MerkleSignedLog.verify(events, c2, self.registry)
        self.assertFalse(ok2_revoked)

    def test_equivocation_detection(self) -> None:
        events = generate_synthetic_events(12, 77)
        c = MerkleSignedLog.commit(events, self.private_path, self.registry.active_key_id)
        forked = AttackSuite.insert(events, 77)
        ok, _ = MerkleSignedLog.verify(forked, c, self.registry)
        self.assertFalse(ok)

    def test_witness_anchor_detects_rollback(self) -> None:
        old_events = generate_synthetic_events(12, 77)
        new_events = old_events + generate_synthetic_events(4, 78)
        old_commitment = MerkleSignedLog.commit(old_events, self.private_path, self.registry.active_key_id)
        new_commitment = MerkleSignedLog.commit(new_events, self.private_path, self.registry.active_key_id)
        witness = WitnessAnchorLog(os.path.join(self.tmp, "witness.jsonl"))
        witness.append(old_commitment, timestamp=1700000000)
        witness.append(new_commitment, timestamp=1700000001)
        self.assertTrue(witness.verify_chain())
        rolled_back, reason = witness.detect_rollback(old_commitment)
        self.assertTrue(rolled_back)
        self.assertEqual(reason, "commitment_older_than_witness")
        current_rollback, current_reason = witness.detect_rollback(new_commitment)
        self.assertFalse(current_rollback)
        self.assertEqual(current_reason, "matches_latest_anchor")

    def test_sqlite_audit_baseline_detects_tamper(self) -> None:
        events = generate_synthetic_events(15, 91)
        db_path = os.path.join(self.tmp, "audit.db")
        commitment = SQLiteAuditBaseline.build(events, db_path)
        self.assertTrue(SQLiteAuditBaseline.verify(events, commitment)[0])
        tampered = AttackSuite.modify(events, 91)
        self.assertFalse(SQLiteAuditBaseline.verify(tampered, commitment)[0])


if __name__ == "__main__":
    unittest.main()
