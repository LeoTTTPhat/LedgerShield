import json
import os
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Dict, Iterable, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common import Event, ensure_parent_dir, write_json
from merkle_signed_log import KeyRegistry, MerkleCommitment


GENESIS_CHECKPOINT_HASH = "0" * 64


def _canonical(payload: Dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(payload: Dict) -> str:
    return sha256(_canonical(payload)).hexdigest()


def _load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        private = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return private


def _load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        public = serialization.load_pem_public_key(f.read())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return public


def _write_private_key(path: str, private: Ed25519PrivateKey) -> None:
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def _write_public_key(path: str, public: Ed25519PublicKey) -> None:
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(
            public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


@dataclass
class PolicyCheckpoint:
    root_hash: str
    tree_size: int
    key_id: str
    sequence: int
    previous_checkpoint_hash: str
    signature_hex: str
    checkpoint_hash: str

    def unsigned_payload(self) -> Dict:
        return {
            "key_id": self.key_id,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "root_hash": self.root_hash,
            "sequence": int(self.sequence),
            "tree_size": int(self.tree_size),
        }

    def signed_payload(self) -> Dict:
        payload = self.unsigned_payload()
        payload["signature_hex"] = self.signature_hex
        return payload

    def to_dict(self) -> Dict:
        return asdict(self)

    @staticmethod
    def from_dict(payload: Dict) -> "PolicyCheckpoint":
        return PolicyCheckpoint(
            root_hash=str(payload["root_hash"]),
            tree_size=int(payload["tree_size"]),
            key_id=str(payload["key_id"]),
            sequence=int(payload["sequence"]),
            previous_checkpoint_hash=str(payload["previous_checkpoint_hash"]),
            signature_hex=str(payload["signature_hex"]),
            checkpoint_hash=str(payload["checkpoint_hash"]),
        )


class PolicySigner:
    """Stateful signer that enforces append-only checkpoint monotonicity."""

    def __init__(self, private_key_path: str, key_id: str, state_path: str):
        self.private_key_path = private_key_path
        self.key_id = key_id
        self.state_path = state_path

    def _load_state(self) -> Dict:
        if not os.path.exists(self.state_path):
            return {
                "last_checkpoint_hash": GENESIS_CHECKPOINT_HASH,
                "last_sequence": 0,
                "last_tree_size": 0,
            }
        with open(self.state_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state: Dict) -> None:
        write_json(self.state_path, state)

    def sign(self, commitment: MerkleCommitment, sequence: int = None) -> PolicyCheckpoint:
        if commitment.key_id != self.key_id:
            raise ValueError("commitment key_id does not match policy signer key_id")

        state = self._load_state()
        last_sequence = int(state.get("last_sequence", 0))
        last_tree_size = int(state.get("last_tree_size", 0))
        if sequence is None:
            sequence = last_sequence + 1
        sequence = int(sequence)

        if sequence <= last_sequence:
            raise ValueError("non-monotone checkpoint sequence")
        if int(commitment.tree_size) < last_tree_size:
            raise ValueError("decreasing tree size")

        previous = str(state.get("last_checkpoint_hash", GENESIS_CHECKPOINT_HASH))
        unsigned = {
            "key_id": self.key_id,
            "previous_checkpoint_hash": previous,
            "root_hash": commitment.root_hash,
            "sequence": sequence,
            "tree_size": int(commitment.tree_size),
        }
        private = _load_private_key(self.private_key_path)
        signature = private.sign(_canonical(unsigned)).hex()
        signed = dict(unsigned)
        signed["signature_hex"] = signature
        checkpoint_hash = _sha256_hex(signed)
        checkpoint = PolicyCheckpoint(
            root_hash=commitment.root_hash,
            tree_size=int(commitment.tree_size),
            key_id=self.key_id,
            sequence=sequence,
            previous_checkpoint_hash=previous,
            signature_hex=signature,
            checkpoint_hash=checkpoint_hash,
        )
        self._save_state(
            {
                "last_checkpoint_hash": checkpoint_hash,
                "last_sequence": sequence,
                "last_tree_size": int(commitment.tree_size),
            }
        )
        return checkpoint


def verify_policy_checkpoint(checkpoint: PolicyCheckpoint, registry: KeyRegistry) -> bool:
    if checkpoint.key_id in registry.revoked_keys:
        return False
    pub_path = registry.keys.get(checkpoint.key_id)
    if not pub_path or not os.path.exists(pub_path):
        return False
    if _sha256_hex(checkpoint.signed_payload()) != checkpoint.checkpoint_hash:
        return False
    try:
        public = _load_public_key(pub_path)
        public.verify(bytes.fromhex(checkpoint.signature_hex), _canonical(checkpoint.unsigned_payload()))
    except Exception:
        return False
    return True


@dataclass
class WitnessCertificate:
    witness_id: str
    checkpoint_hash: str
    sequence: int
    previous_checkpoint_hash: str
    signature_hex: str

    def signed_payload(self) -> Dict:
        return {
            "checkpoint_hash": self.checkpoint_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "sequence": int(self.sequence),
            "witness_id": self.witness_id,
        }

    def to_dict(self) -> Dict:
        return asdict(self)


class QuorumWitness:
    """A witness key that refuses to sign conflicting checkpoints."""

    def __init__(self, witness_id: str, private_key_path: str, public_key_path: str, state_path: str):
        self.witness_id = witness_id
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.state_path = state_path

    @staticmethod
    def create(witness_id: str, key_dir: str, state_dir: str) -> "QuorumWitness":
        os.makedirs(key_dir, exist_ok=True)
        os.makedirs(state_dir, exist_ok=True)
        private_path = os.path.join(key_dir, f"{witness_id}_private.pem")
        public_path = os.path.join(key_dir, f"{witness_id}_public.pem")
        if not os.path.exists(private_path) or not os.path.exists(public_path):
            private = Ed25519PrivateKey.generate()
            _write_private_key(private_path, private)
            _write_public_key(public_path, private.public_key())
        return QuorumWitness(
            witness_id=witness_id,
            private_key_path=private_path,
            public_key_path=public_path,
            state_path=os.path.join(state_dir, f"{witness_id}.json"),
        )

    def _load_state(self) -> Dict:
        if not os.path.exists(self.state_path):
            return {"signed": {}}
        with open(self.state_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state: Dict) -> None:
        write_json(self.state_path, state)

    def sign_checkpoint(self, checkpoint: PolicyCheckpoint) -> WitnessCertificate:
        state = self._load_state()
        signed = state.setdefault("signed", {})
        slot = f"{checkpoint.sequence}:{checkpoint.previous_checkpoint_hash}"
        existing = signed.get(slot)
        if existing and existing != checkpoint.checkpoint_hash:
            raise ValueError("conflicting checkpoint for witness slot")

        payload = {
            "checkpoint_hash": checkpoint.checkpoint_hash,
            "previous_checkpoint_hash": checkpoint.previous_checkpoint_hash,
            "sequence": int(checkpoint.sequence),
            "witness_id": self.witness_id,
        }
        private = _load_private_key(self.private_key_path)
        certificate = WitnessCertificate(
            witness_id=self.witness_id,
            checkpoint_hash=checkpoint.checkpoint_hash,
            sequence=int(checkpoint.sequence),
            previous_checkpoint_hash=checkpoint.previous_checkpoint_hash,
            signature_hex=private.sign(_canonical(payload)).hex(),
        )
        signed[slot] = checkpoint.checkpoint_hash
        self._save_state(state)
        return certificate


def verify_witness_certificate(
    certificate: WitnessCertificate, checkpoint: PolicyCheckpoint, witness_public_key_path: str
) -> bool:
    if certificate.checkpoint_hash != checkpoint.checkpoint_hash:
        return False
    if int(certificate.sequence) != int(checkpoint.sequence):
        return False
    if certificate.previous_checkpoint_hash != checkpoint.previous_checkpoint_hash:
        return False
    if not os.path.exists(witness_public_key_path):
        return False
    try:
        public = _load_public_key(witness_public_key_path)
        public.verify(bytes.fromhex(certificate.signature_hex), _canonical(certificate.signed_payload()))
    except Exception:
        return False
    return True


def verify_quorum(
    checkpoint: PolicyCheckpoint,
    certificates: Iterable[WitnessCertificate],
    witness_public_keys: Dict[str, str],
    threshold: int,
) -> bool:
    if threshold <= 0:
        raise ValueError("threshold must be positive")
    seen = set()
    valid = 0
    for certificate in certificates:
        if certificate.witness_id in seen:
            return False
        seen.add(certificate.witness_id)
        pub_path = witness_public_keys.get(certificate.witness_id)
        if pub_path and verify_witness_certificate(certificate, checkpoint, pub_path):
            valid += 1
    return valid >= threshold


def source_id_from_reference(event: Event) -> str:
    fields = {}
    for part in event.reference.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.strip().lower()] = value.strip()
    for key in ("source", "source_id", "trans", "transaction", "txid"):
        if key in fields and fields[key]:
            return fields[key]
    return event.reference


def audit_completeness(events: List[Event], expected_source_ids: Iterable[str]) -> Dict:
    expected = [str(x) for x in expected_source_ids]
    observed = [source_id_from_reference(event) for event in events]
    expected_set = set(expected)
    observed_set = set(observed)
    duplicates = sorted({source_id for source_id in observed if observed.count(source_id) > 1})
    missing = sorted(expected_set - observed_set)
    extra = sorted(observed_set - expected_set)
    return {
        "complete": not missing and not extra and not duplicates,
        "duplicate_ids": duplicates,
        "expected_count": len(expected),
        "extra_ids": extra,
        "missing_ids": missing,
        "present_count": len(observed),
    }


def make_conflicting_checkpoint(checkpoint: PolicyCheckpoint, root_hash: str) -> PolicyCheckpoint:
    payload = checkpoint.unsigned_payload()
    payload["root_hash"] = root_hash
    payload["signature_hex"] = checkpoint.signature_hex
    return PolicyCheckpoint(
        root_hash=root_hash,
        tree_size=checkpoint.tree_size,
        key_id=checkpoint.key_id,
        sequence=checkpoint.sequence,
        previous_checkpoint_hash=checkpoint.previous_checkpoint_hash,
        signature_hex=checkpoint.signature_hex,
        checkpoint_hash=_sha256_hex(payload),
    )
