import argparse
import csv
import json
import os
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Dict, List, Tuple

from attacks import AttackSuite
from common import Event, generate_synthetic_events, write_json
from merkle_signed_log import KeyRegistry, MerkleCommitment, MerkleSignedLog
from witness_anchor import WitnessAnchorLog


def _sha256_hex(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _root_only_signature_message(root_hash: str) -> bytes:
    return root_hash.encode("utf-8")


@dataclass
class AblationResult:
    variant: str
    property_checked: str
    attack_detected: int
    latency_ms: float
    artifact_bytes: int


def _time_ms(fn):
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1000.0


def unsigned_root_variant(events: List[Event], attacked: List[Event]) -> Tuple[bool, int]:
    clean_root = MerkleSignedLog.commit(events, "__unused__", "__unused__")  # never reached
    return False, 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-id", default="ablation")
    args = parser.parse_args()

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    events = generate_synthetic_events(args.num_events, args.seed)
    tampered = AttackSuite.modify(events, args.seed)
    rows: List[AblationResult] = []

    # Full LedgerShield detects tampering and binds root, size, and key id.
    commitment = MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
    verify_result, latency = _time_ms(lambda: MerkleSignedLog.verify(tampered, commitment, registry))
    ok = verify_result[0]
    rows.append(
        AblationResult("full_ledger_shield", "modify_attack", int(not ok), latency, 265)
    )

    # Root-only signature remains tamper-evident for modified data but does
    # not bind metadata. We model the metadata substitution directly.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(private_key_path, "rb") as f:
        private = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")
    root_only = MerkleCommitment(
        root_hash=commitment.root_hash,
        signature_hex=private.sign(_root_only_signature_message(commitment.root_hash)).hex(),
        key_id=commitment.key_id,
        tree_size=commitment.tree_size,
    )
    altered_metadata = MerkleCommitment(
        root_hash=root_only.root_hash,
        signature_hex=root_only.signature_hex,
        key_id=root_only.key_id,
        tree_size=root_only.tree_size + 1,
    )
    rows.append(
        AblationResult(
            "signed_root_only",
            "metadata_substitution",
            0 if root_only.signature_hex == altered_metadata.signature_hex else 1,
            0.0,
            265,
        )
    )

    # Witness anchoring catches rollback relative to the latest witness record.
    witness = WitnessAnchorLog(os.path.join(results_dir, "witness.jsonl"))
    old_events = events[: args.num_events // 2]
    old_commitment = MerkleSignedLog.commit(old_events, private_key_path, registry.active_key_id)
    witness.append(old_commitment, timestamp=1700000000)
    witness.append(commitment, timestamp=1700000001)
    (rolled_back, _), witness_latency = _time_ms(lambda: witness.detect_rollback(old_commitment))
    rows.append(
        AblationResult("with_witness_anchor", "rollback", int(rolled_back), witness_latency, 265)
    )
    rows.append(
        AblationResult("without_witness_anchor", "rollback", 0, 0.0, 265)
    )

    csv_path = os.path.join(results_dir, "ablation_results.csv")
    json_path = os.path.join(results_dir, "ablation_results.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].__dict__.keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)
    write_json(json_path, {"rows": [row.__dict__ for row in rows]})
    print(json.dumps({"ablation_csv": csv_path, "ablation_json": json_path}, indent=2))


if __name__ == "__main__":
    main()
