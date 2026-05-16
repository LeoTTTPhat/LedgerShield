import json
import os
from hashlib import sha256
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common import Event, ensure_parent_dir


def _sha256_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _hash_leaf(data: str) -> str:
    raw = data.encode("utf-8")
    return _sha256_bytes(b"\x00" + len(raw).to_bytes(8, "big") + raw)


def _hash_node(left_hex: str, right_hex: str) -> str:
    return _sha256_bytes(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _hash_pair(left: str, right: str) -> str:
    return _hash_node(left, right)


def _build_levels(leaves: List[str]) -> List[List[str]]:
    # Kept only for backward compatibility with old call sites.
    if not leaves:
        return [[_sha256_bytes(b"\x02")]]
    return [leaves[:], [_build_root(leaves)]]


def _build_root(leaves: List[str]) -> str:
    n = len(leaves)
    if n == 0:
        return _sha256_bytes(b"\x02")
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_less_than(n)
    return _hash_pair(_build_root(leaves[:k]), _build_root(leaves[k:]))


def _event_leaf(event: Event) -> str:
    return _hash_leaf(event.canonical_json())


def _commitment_message(root_hash: str, tree_size: int, key_id: str) -> bytes:
    payload = {
        "key_id": key_id,
        "root_hash": root_hash,
        "tree_size": int(tree_size),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _largest_power_of_two_less_than(n: int) -> int:
    if n < 2:
        return 0
    p = 1
    while (p << 1) < n:
        p <<= 1
    return p


def _range_root(leaves: List[str], start: int, size: int) -> str:
    if size <= 0:
        return _sha256_bytes(b"\x02")
    return _build_root(leaves[start : start + size])


def _ct_subproof_hashes(leaves: List[str], m: int, n: int, b: bool, start: int = 0) -> List[str]:
    if m <= 0 or n <= 0 or m > n:
        raise ValueError("invalid sizes for consistency proof")
    if m == n:
        return [] if b else [_range_root(leaves, start, n)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _ct_subproof_hashes(leaves, m, k, b, start) + [_range_root(leaves, start + k, n - k)]
    return _ct_subproof_hashes(leaves, m - k, n - k, False, start + k) + [_range_root(leaves, start, k)]


def _ct_consistency_proof_hashes(leaves: List[str], m: int, n: int) -> List[str]:
    return _ct_subproof_hashes(leaves, m, n, True, 0)


def _ct_consistency_proof_length(m: int, n: int, b: bool = True) -> int:
    if m <= 0 or n <= 0 or m > n:
        raise ValueError("invalid sizes for consistency proof length")
    if m == n:
        return 0 if b else 1
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _ct_consistency_proof_length(m, k, b) + 1
    return _ct_consistency_proof_length(m - k, n - k, False) + 1


@dataclass
class MerkleCommitment:
    root_hash: str
    signature_hex: str
    key_id: str
    tree_size: int

    def to_dict(self) -> Dict:
        return asdict(self)

    @staticmethod
    def from_dict(payload: Dict) -> "MerkleCommitment":
        return MerkleCommitment(
            root_hash=payload["root_hash"],
            signature_hex=payload["signature_hex"],
            key_id=payload["key_id"],
            tree_size=int(payload["tree_size"]),
        )


@dataclass
class KeyRegistry:
    active_key_id: str
    keys: Dict[str, str]
    revoked_keys: List[str]

    @staticmethod
    def init_or_load(path: str, key_dir: str, default_key_id: str = "k1") -> "KeyRegistry":
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            return KeyRegistry(
                active_key_id=payload["active_key_id"],
                keys=payload["keys"],
                revoked_keys=payload.get("revoked_keys", []),
            )

        os.makedirs(key_dir, exist_ok=True)
        priv_path = os.path.join(key_dir, f"{default_key_id}_private.pem")
        pub_path = os.path.join(key_dir, f"{default_key_id}_public.pem")
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        with open(priv_path, "wb") as f:
            f.write(
                private.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(pub_path, "wb") as f:
            f.write(
                public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        registry = KeyRegistry(
            active_key_id=default_key_id,
            keys={default_key_id: pub_path},
            revoked_keys=[],
        )
        registry.save(path)
        return registry

    def save(self, path: str) -> None:
        ensure_parent_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "active_key_id": self.active_key_id,
                    "keys": self.keys,
                    "revoked_keys": self.revoked_keys,
                },
                f,
                indent=2,
                sort_keys=True,
            )

    def rotate_key(self, path: str, key_dir: str) -> str:
        next_key_id = f"k{len(self.keys) + 1}"
        os.makedirs(key_dir, exist_ok=True)
        priv_path = os.path.join(key_dir, f"{next_key_id}_private.pem")
        pub_path = os.path.join(key_dir, f"{next_key_id}_public.pem")
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        with open(priv_path, "wb") as f:
            f.write(
                private.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(pub_path, "wb") as f:
            f.write(
                public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        self.active_key_id = next_key_id
        self.keys[next_key_id] = pub_path
        self.save(path)
        return next_key_id

    def revoke_key(self, key_id: str, path: str) -> None:
        if key_id not in self.revoked_keys:
            self.revoked_keys.append(key_id)
        self.save(path)


class MerkleSignedLog:
    @staticmethod
    def leaves(events: List[Event]) -> List[str]:
        return [_event_leaf(e) for e in events]

    @staticmethod
    def commit(events: List[Event], private_key_path: str, key_id: str) -> MerkleCommitment:
        leaves = MerkleSignedLog.leaves(events)
        root = _build_root(leaves)
        with open(private_key_path, "rb") as f:
            private = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("Private key must be Ed25519")
        signature = private.sign(_commitment_message(root, len(leaves), key_id)).hex()
        return MerkleCommitment(
            root_hash=root,
            signature_hex=signature,
            key_id=key_id,
            tree_size=len(leaves),
        )

    @staticmethod
    def verify(events: List[Event], commitment: MerkleCommitment, registry: KeyRegistry) -> Tuple[bool, int]:
        if commitment.key_id in registry.revoked_keys:
            return False, 0
        pub_path = registry.keys.get(commitment.key_id)
        if not pub_path or not os.path.exists(pub_path):
            return False, 0
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        if not isinstance(pub, Ed25519PublicKey):
            return False, 0
        leaves = MerkleSignedLog.leaves(events)
        if commitment.tree_size != len(leaves):
            return False, 0
        root = _build_root(leaves)
        try:
            pub.verify(
                bytes.fromhex(commitment.signature_hex),
                _commitment_message(commitment.root_hash, commitment.tree_size, commitment.key_id),
            )
        except Exception:
            return False, 0
        return root == commitment.root_hash, MerkleSignedLog.estimated_proof_size(len(leaves))

    @staticmethod
    def estimated_proof_size(num_leaves: int) -> int:
        return 32 * max(1, (num_leaves - 1).bit_length())

    @staticmethod
    def gen_inclusion_proof(events: List[Event], index: int) -> List[Tuple[str, str]]:
        leaves = MerkleSignedLog.leaves(events)
        if index < 0 or index >= len(leaves):
            raise IndexError("index out of range")

        def rec(cur: List[str], idx: int) -> List[Tuple[str, str]]:
            if len(cur) <= 1:
                return []
            k = _largest_power_of_two_less_than(len(cur))
            left = cur[:k]
            right = cur[k:]
            if idx < k:
                return rec(left, idx) + [("R", _build_root(right))]
            return rec(right, idx - k) + [("L", _build_root(left))]

        return rec(leaves, index)

    @staticmethod
    def verify_inclusion_proof(event: Event, index: int, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        cur = _event_leaf(event)
        idx = index
        for side, sibling in proof:
            if side == "R":
                cur = _hash_pair(cur, sibling)
            elif side == "L":
                cur = _hash_pair(sibling, cur)
            else:
                return False
            idx //= 2
        return cur == root_hash

    @staticmethod
    def gen_consistency_proof(
        old_events: List[Event],
        new_events: List[Event],
        private_key_path: str = "",
        key_id: str = "",
    ) -> Dict:
        if len(old_events) > len(new_events):
            raise ValueError("old_events cannot be longer than new_events")
        if len(old_events) == 0:
            raise ValueError("old_events must be non-empty")
        old_leaves = MerkleSignedLog.leaves(old_events)
        new_leaves = MerkleSignedLog.leaves(new_events)
        old_size = len(old_leaves)
        new_size = len(new_leaves)
        proof_hashes = _ct_consistency_proof_hashes(new_leaves, old_size, new_size)
        proof = {
            "scheme": "ct_style_consistency_v1",
            "old_size": old_size,
            "new_size": new_size,
            "old_root": _build_root(old_leaves),
            "new_root": _build_root(new_leaves),
            "proof_hashes": proof_hashes,
        }
        if private_key_path and key_id:
            with open(private_key_path, "rb") as f:
                private = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise ValueError("Private key must be Ed25519")
            message = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
            proof["proof_key_id"] = key_id
            proof["proof_signature_hex"] = private.sign(message).hex()
        return proof

    @staticmethod
    def verify_consistency_proof(proof: Dict, new_events: List[Event]) -> bool:
        try:
            old_size = int(proof["old_size"])
            new_size = int(proof["new_size"])
            old_root = proof["old_root"]
            new_root = proof["new_root"]
            proof_hashes = proof["proof_hashes"]
        except Exception:
            return False
        if old_size <= 0 or old_size > new_size:
            return False
        new_leaves = MerkleSignedLog.leaves(new_events)
        if len(new_leaves) != new_size:
            return False
        expected_hashes = _ct_consistency_proof_hashes(new_leaves, old_size, new_size)
        if proof_hashes != expected_hashes:
            return False
        old_root_from_new = _build_root(new_leaves[:old_size])
        new_root_from_new = _build_root(new_leaves)
        return old_root_from_new == old_root and new_root_from_new == new_root

    @staticmethod
    def verify_consistency_proof_external(proof: Dict, registry: KeyRegistry = None) -> bool:
        try:
            old_size = int(proof["old_size"])
            new_size = int(proof["new_size"])
            old_root = proof["old_root"]
            new_root = proof["new_root"]
            proof_hashes = proof["proof_hashes"]
        except Exception:
            return False
        if old_size <= 0 or old_size > new_size or not isinstance(proof_hashes, list):
            return False
        if not (isinstance(old_root, str) and isinstance(new_root, str) and len(old_root) == 64 and len(new_root) == 64):
            return False
        try:
            expected_len = _ct_consistency_proof_length(old_size, new_size, True)
        except Exception:
            return False
        if len(proof_hashes) != expected_len:
            return False
        for h in proof_hashes:
            if not isinstance(h, str) or len(h) != 64:
                return False
            try:
                bytes.fromhex(h)
            except Exception:
                return False
        relation_ok = False
        if old_size == new_size:
            relation_ok = old_root == new_root and len(proof_hashes) == 0
        elif len(proof_hashes) != 0:
            fn = old_size - 1
            sn = new_size - 1
            if (old_size & (old_size - 1)) == 0:
                fr = old_root
                sr = old_root
                idx = 0
            else:
                fr = proof_hashes[0]
                sr = proof_hashes[0]
                idx = 1
            while fn & 1:
                fn >>= 1
                sn >>= 1

            while idx < len(proof_hashes):
                h = proof_hashes[idx]
                idx += 1
                if sn == 0:
                    return False
                if (fn & 1) or (fn == sn):
                    fr = _hash_node(h, fr)
                    sr = _hash_node(h, sr)
                    while fn and ((fn & 1) == 0):
                        fn >>= 1
                        sn >>= 1
                else:
                    sr = _hash_node(sr, h)
                fn >>= 1
                sn >>= 1
            relation_ok = fn == 0 and sn == 0 and fr == old_root and sr == new_root
        if not relation_ok:
            return False

        sig_hex = proof.get("proof_signature_hex", "")
        sig_kid = proof.get("proof_key_id", "")
        if sig_hex or sig_kid:
            if registry is None or not sig_hex or not sig_kid:
                return False
            if sig_kid in registry.revoked_keys:
                return False
            pub_path = registry.keys.get(sig_kid)
            if not pub_path or not os.path.exists(pub_path):
                return False
            with open(pub_path, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
            if not isinstance(pub, Ed25519PublicKey):
                return False
            unsigned = {
                "scheme": proof["scheme"],
                "old_size": old_size,
                "new_size": new_size,
                "old_root": old_root,
                "new_root": new_root,
                "proof_hashes": proof_hashes,
            }
            message = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            try:
                pub.verify(bytes.fromhex(sig_hex), message)
            except Exception:
                return False
        return True
