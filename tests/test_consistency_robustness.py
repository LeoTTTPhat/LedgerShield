import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from common import generate_synthetic_events
from merkle_signed_log import KeyRegistry, MerkleSignedLog


class TestConsistencyRobustness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="auditlog_robust_")
        self.key_dir = os.path.join(self.tmp, "keys")
        self.registry_path = os.path.join(self.tmp, "registry.json")
        self.registry = KeyRegistry.init_or_load(self.registry_path, self.key_dir)
        self.private_path = os.path.join(self.key_dir, f"{self.registry.active_key_id}_private.pem")
        old = generate_synthetic_events(32, 11)
        new = old + generate_synthetic_events(9, 12)
        self.valid_proof = MerkleSignedLog.gen_consistency_proof(old, new)
        self.signed_proof = MerkleSignedLog.gen_consistency_proof(
            old, new, private_key_path=self.private_path, key_id=self.registry.active_key_id
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reject_malformed_corpus(self) -> None:
        corpus = [
            {},
            {"old_size": 10},
            {"old_size": 10, "new_size": 5, "old_root": "a" * 64, "new_root": "b" * 64, "proof_hashes": []},
            {"old_size": 10, "new_size": 20, "old_root": "x", "new_root": "b" * 64, "proof_hashes": []},
            {"old_size": 10, "new_size": 20, "old_root": "a" * 64, "new_root": "b" * 64, "proof_hashes": "notalist"},
            {"old_size": 10, "new_size": 20, "old_root": "a" * 64, "new_root": "b" * 64, "proof_hashes": ["zz"]},
        ]
        for p in corpus:
            self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(p))

    def test_reject_single_bitflip_like_tampering(self) -> None:
        p = dict(self.valid_proof)
        hashes = list(p["proof_hashes"])
        if not hashes:
            self.skipTest("proof list empty for this shape")
        h0 = hashes[0]
        mutated = ("0" if h0[0] != "0" else "1") + h0[1:]
        hashes[0] = mutated
        p["proof_hashes"] = hashes
        self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(p))

    def test_property_random_mutations_rejected(self) -> None:
        base = self.valid_proof
        mutations = []

        p1 = dict(base)
        p1["old_size"] = int(base["old_size"]) + 1
        mutations.append(p1)

        p2 = dict(base)
        p2["new_size"] = int(base["new_size"]) - 1
        p2["new_root"] = ("0" if base["new_root"][0] != "0" else "1") + base["new_root"][1:]
        mutations.append(p2)

        p3 = dict(base)
        p3["old_root"] = ("0" if base["old_root"][0] != "0" else "1") + base["old_root"][1:]
        mutations.append(p3)

        p4 = dict(base)
        p4["new_root"] = ("0" if base["new_root"][0] != "0" else "1") + base["new_root"][1:]
        mutations.append(p4)

        if base["proof_hashes"]:
            p5 = dict(base)
            p5["proof_hashes"] = list(base["proof_hashes"])
            h = p5["proof_hashes"][0]
            p5["proof_hashes"][0] = ("0" if h[0] != "0" else "1") + h[1:]
            mutations.append(p5)

        for p in mutations:
            self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(p))

    def test_signed_proof_binds_tuple(self) -> None:
        self.assertTrue(MerkleSignedLog.verify_consistency_proof_external(self.signed_proof, self.registry))
        tampered = dict(self.signed_proof)
        tampered["new_size"] = int(self.signed_proof["new_size"]) - 1
        self.assertFalse(MerkleSignedLog.verify_consistency_proof_external(tampered, self.registry))


if __name__ == "__main__":
    unittest.main()
