"""run_head_to_head.py – Non-production architectural model comparison.

This script is intentionally not a live Trillian or immudb benchmark. It keeps
simple in-process architectural models for local algorithmic sanity checks only.
Do not report its output as production performance, deployment equivalence, or
a live comparison with real services.

The two models sketch selected architectural behaviours:

  Trillian-model:  RFC 6962-style Merkle log with a batched "sequence" phase that
    groups leaves into a fixed batch before extending the tree.  After sequencing,
    produces an STH (Signed Tree Head) over (root, tree_size).  Inclusion proofs
    are O(log N) sibling hashes.  Consistency proofs follow RFC 6962 §2.1.2.
    Signing uses HMAC-SHA256 over the STH payload as a local placeholder;
    this is not Trillian's production signer path.

  immudb-model:  Append-only key-value store where each entry is identified by a
    monotonic transaction ID (tx_id).  The Merkle tree is maintained over
    (tx_id, value_hash) pairs.  An inclusion proof for a given tx_id is an
    O(log N) path.  immudb does NOT produce signed STHs by default; the
    "commitment" here is the raw root hash stored in the transaction header,
    modelling the linear-history guarantees documented in the immudb white paper.

Both models execute hashing, proof generation, and proof verification in the
same Python process, on the same hardware, with the same workload bytes. They
exclude network, database I/O, sequencing services, batching policy, RPC
overheads, signer configuration, and production storage behaviour.

Usage:
    python src/run_head_to_head.py \
        --sizes 1000,10000,100000 \
        --seed 42 \
        --repetitions 5 \
        --workload calibrated \
        --run-id head_to_head
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import statistics
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

from common import generate_events, write_json, Event
from merkle_signed_log import (
    KeyRegistry,
    MerkleSignedLog,
    _build_root,
    _hash_leaf,
    _hash_node,
    _largest_power_of_two_less_than,
    _ct_consistency_proof_hashes,
    _ct_consistency_proof_length,
)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def timed_ms(fn):
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1000.0


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def summarize_samples(samples: List[float]) -> Dict[str, float]:
    return {
        "p50_ms": percentile(samples, 50),
        "p95_ms": percentile(samples, 95),
        "mean_ms": statistics.mean(samples) if samples else 0.0,
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
    }


# ---------------------------------------------------------------------------
# Trillian-style architectural model
# ---------------------------------------------------------------------------

_TRILLIAN_BATCH = 256          # default Trillian sequencer batch size
_TRILLIAN_HMAC_KEY = b"ledgershield-h2h-trillian-key"  # stable key for signing


@dataclass
class TrillianSTH:
    """Signed Tree Head: root_hash, tree_size, hmac_hex."""
    root_hash: str
    tree_size: int
    hmac_hex: str   # HMAC-SHA256 over (root_hash || tree_size as 8-byte BE)


class TrillianModel:
    """
    RFC 6962-style Merkle log with batched sequencing.

    Architecture notes (from google/trillian README and RFC 6962 §2):
    - Leaves are enqueued and sequenced in batches (default 256/tick).
    - The tree is built using the same RFC 6962 balanced-append scheme as
      LedgerShield (domain-separated leaf and node hashes).
    - The STH is signed over (root, tree_size); here we use HMAC-SHA256 as
      a stand-in for the Trillian ECDSA/Ed25519 signer to avoid loading
      additional keys, keeping the signing cost comparable but slightly lower
      than LedgerShield's Ed25519.
    """

    @staticmethod
    def _sth_payload(root_hash: str, tree_size: int) -> bytes:
        return root_hash.encode() + tree_size.to_bytes(8, "big")

    @staticmethod
    def _sign_sth(root_hash: str, tree_size: int) -> str:
        payload = TrillianModel._sth_payload(root_hash, tree_size)
        return hmac.new(_TRILLIAN_HMAC_KEY, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def commit(events: List[Event]) -> Tuple[TrillianSTH, List[str]]:
        """Build tree with batched sequencing; return STH and leaf list."""
        # Batch-sequence: process leaves in chunks of _TRILLIAN_BATCH
        all_leaves: List[str] = []
        for i in range(0, len(events), _TRILLIAN_BATCH):
            batch = events[i : i + _TRILLIAN_BATCH]
            for e in batch:
                all_leaves.append(_hash_leaf(e.canonical_json()))
        root = _build_root(all_leaves) if all_leaves else _build_root([])
        hmac_hex = TrillianModel._sign_sth(root, len(all_leaves))
        return TrillianSTH(root_hash=root, tree_size=len(all_leaves), hmac_hex=hmac_hex), all_leaves

    @staticmethod
    def verify_sth(sth: TrillianSTH) -> bool:
        expected = TrillianModel._sign_sth(sth.root_hash, sth.tree_size)
        return hmac.compare_digest(expected, sth.hmac_hex)

    @staticmethod
    def gen_inclusion_proof(leaves: List[str], index: int) -> List[Tuple[str, str]]:
        """Same O(log N) sibling-path algorithm as LedgerShield."""
        def rec(cur: List[str], idx: int) -> List[Tuple[str, str]]:
            if len(cur) <= 1:
                return []
            k = _largest_power_of_two_less_than(len(cur))
            left, right = cur[:k], cur[k:]
            if idx < k:
                return rec(left, idx) + [("R", _build_root(right))]
            return rec(right, idx - k) + [("L", _build_root(left))]
        return rec(leaves, index)

    @staticmethod
    def verify_inclusion_proof(event: Event, index: int, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        cur = _hash_leaf(event.canonical_json())
        for side, sibling in proof:
            if side == "R":
                cur = _hash_node(cur, sibling)
            elif side == "L":
                cur = _hash_node(sibling, cur)
            else:
                return False
        return cur == root_hash

    @staticmethod
    def gen_consistency_proof(leaves: List[str], old_size: int) -> List[str]:
        n = len(leaves)
        if old_size <= 0 or old_size > n:
            return []
        return _ct_consistency_proof_hashes(leaves, old_size, n)

    @staticmethod
    def verify_consistency_proof(leaves: List[str], old_size: int, proof_hashes: List[str]) -> bool:
        n = len(leaves)
        if old_size <= 0 or old_size > n:
            return False
        expected = _ct_consistency_proof_hashes(leaves, old_size, n)
        return expected == proof_hashes

    @staticmethod
    def sth_bytes(sth: TrillianSTH) -> int:
        return len(json.dumps(asdict(sth)).encode())

    @staticmethod
    def inclusion_proof_bytes(proof: List[Tuple[str, str]]) -> int:
        return len(json.dumps(proof).encode())


# ---------------------------------------------------------------------------
# immudb-style architectural model
# ---------------------------------------------------------------------------

@dataclass
class ImmudbTxHeader:
    """
    Per-transaction header as documented in the immudb white paper (v1.x).
    Fields: tx_id, prev_alh (accumulated linear hash), entry_count, root_hash.
    The 'alh' (Accumulated Linear Hash) chains transactions: 
      alh_n = SHA256(tx_n_hash || alh_{n-1}).
    """
    tx_id: int
    entry_count: int
    root_hash: str    # Merkle root over entries in this tx
    alh: str          # accumulated linear hash (forward chaining)

    def to_dict(self) -> Dict:
        return asdict(self)


class ImmudbModel:
    """
    Append-only key-value store with Merkle proofs, modelling immudb v1.x.

    Architecture notes (from immudb white paper and source code):
    - Each transaction has a monotonic tx_id and covers one or more KV pairs.
    - A Merkle tree is built over the KV entry hashes within the transaction.
    - The accumulated linear hash (ALH) provides forward integrity across txs:
        alh_n = SHA256(alh_{n-1} || tx_n.root_hash || tx_n_id.to_bytes(8))
    - Inclusion proofs are produced over a second-level tree built from all
      individual tx root hashes (the "dual-proof" structure). Here we simplify
      to a flat tree over all entry hashes (single-level proof) as used in
      immudb's VerifiedGet path.
    - There is no separate signing step in the default open-source immudb;
      tamper evidence comes from the ALH chain + Merkle tree.
    """

    @staticmethod
    def _entry_hash(event: Event) -> str:
        raw = event.canonical_json().encode("utf-8")
        # immudb entry hash: SHA256(key_len || key || value_hash)
        key = f"evt_{event.event_id}".encode()
        value_hash = hashlib.sha256(raw).digest()
        payload = len(key).to_bytes(4, "big") + key + value_hash
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _compute_alh(prev_alh: str, root_hash: str, tx_id: int) -> str:
        payload = bytes.fromhex(prev_alh) + bytes.fromhex(root_hash) + tx_id.to_bytes(8, "big")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def build(events: List[Event]) -> Tuple[List[ImmudbTxHeader], List[str], str]:
        """
        Build immudb-model transaction log.
        Returns (headers, all_entry_hashes, final_alh).
        Each event is its own transaction (matching VerifiedSet usage).
        """
        ZERO_ALH = "0" * 64
        entry_hashes: List[str] = []
        headers: List[ImmudbTxHeader] = []
        alh = ZERO_ALH
        for i, event in enumerate(events):
            eh = ImmudbModel._entry_hash(event)
            entry_hashes.append(eh)
            root = _build_root([eh])   # single-entry tx; root == leaf hash
            tx_id = i + 1
            alh = ImmudbModel._compute_alh(alh, root, tx_id)
            headers.append(ImmudbTxHeader(
                tx_id=tx_id,
                entry_count=1,
                root_hash=root,
                alh=alh,
            ))
        # Build global inclusion tree over all entry hashes (dual-proof level 2)
        global_root = _build_root(entry_hashes) if entry_hashes else _build_root([])
        return headers, entry_hashes, global_root

    @staticmethod
    def verify_alh_chain(headers: List[ImmudbTxHeader]) -> bool:
        ZERO_ALH = "0" * 64
        prev_alh = ZERO_ALH
        for hdr in headers:
            expected_alh = ImmudbModel._compute_alh(prev_alh, hdr.root_hash, hdr.tx_id)
            if expected_alh != hdr.alh:
                return False
            prev_alh = hdr.alh
        return True

    @staticmethod
    def gen_inclusion_proof(entry_hashes: List[str], index: int) -> List[Tuple[str, str]]:
        """O(log N) inclusion proof over the global entry hash tree."""
        def rec(cur: List[str], idx: int) -> List[Tuple[str, str]]:
            if len(cur) <= 1:
                return []
            k = _largest_power_of_two_less_than(len(cur))
            left, right = cur[:k], cur[k:]
            if idx < k:
                return rec(left, idx) + [("R", _build_root(right))]
            return rec(right, idx - k) + [("L", _build_root(left))]
        return rec(entry_hashes, index)

    @staticmethod
    def verify_inclusion_proof(event: Event, index: int, proof: List[Tuple[str, str]], global_root: str) -> bool:
        cur = ImmudbModel._entry_hash(event)
        for side, sibling in proof:
            if side == "R":
                cur = _hash_node(cur, sibling)
            elif side == "L":
                cur = _hash_node(sibling, cur)
            else:
                return False
        return cur == global_root

    @staticmethod
    def commitment_bytes(headers: List[ImmudbTxHeader], global_root: str) -> int:
        """Commitment = last ALH header + global root (minimal verifiable state)."""
        if not headers:
            return 32
        last = headers[-1].to_dict()
        return len(json.dumps(last).encode()) + 32

    @staticmethod
    def inclusion_proof_bytes(proof: List[Tuple[str, str]]) -> int:
        return len(json.dumps(proof).encode())


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def benchmark_size(
    size: int,
    seed: int,
    repetitions: int,
    workload: str,
    registry: KeyRegistry,
    private_key_path: str,
) -> Dict:
    events = generate_events(size, seed, workload)
    pivot = max(1, size // 2)
    old_events = events[:pivot]

    # ---- LedgerShield ----
    ls_commit, ls_commit_ms = timed_ms(
        lambda: MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
    )
    ls_proof, ls_proof_gen_ms = timed_ms(
        lambda: MerkleSignedLog.gen_inclusion_proof(events, pivot)
    )
    ls_consistency, ls_cons_gen_ms = timed_ms(
        lambda: MerkleSignedLog.gen_consistency_proof(
            old_events, events, private_key_path, registry.active_key_id
        )
    )
    ls_verify_samples = []
    ls_incl_samples = []
    ls_cons_samples = []
    for _ in range(repetitions):
        ls_verify_samples.append(
            timed_ms(lambda: MerkleSignedLog.verify(events, ls_commit, registry))[1]
        )
        ls_incl_samples.append(
            timed_ms(lambda: MerkleSignedLog.verify_inclusion_proof(
                events[pivot], pivot, ls_proof, ls_commit.root_hash
            ))[1]
        )
        ls_cons_samples.append(
            timed_ms(lambda: MerkleSignedLog.verify_consistency_proof_external(
                ls_consistency, registry
            ))[1]
        )
    ls_proof_bytes = len(json.dumps(ls_proof).encode())
    ls_commit_bytes = len(json.dumps(ls_commit.to_dict(), sort_keys=True).encode())

    # ---- Trillian-model ----
    tr_sth, tr_leaves = None, None
    tr_commit_ms_val = 0.0

    def _tr_commit():
        nonlocal tr_sth, tr_leaves
        tr_sth, tr_leaves = TrillianModel.commit(events)
    _, tr_commit_ms_val = timed_ms(_tr_commit)

    tr_proof, tr_proof_gen_ms = timed_ms(
        lambda: TrillianModel.gen_inclusion_proof(tr_leaves, pivot)
    )
    tr_old_leaves = [_hash_leaf(e.canonical_json()) for e in old_events]
    tr_cons_hashes, tr_cons_gen_ms = timed_ms(
        lambda: TrillianModel.gen_consistency_proof(tr_leaves, len(tr_old_leaves))
    )

    tr_verify_samples = []
    tr_incl_samples = []
    tr_cons_samples = []
    for _ in range(repetitions):
        tr_verify_samples.append(
            timed_ms(lambda: TrillianModel.verify_sth(tr_sth))[1]
        )
        tr_incl_samples.append(
            timed_ms(lambda: TrillianModel.verify_inclusion_proof(
                events[pivot], pivot, tr_proof, tr_sth.root_hash
            ))[1]
        )
        tr_cons_samples.append(
            timed_ms(lambda: TrillianModel.verify_consistency_proof(
                tr_leaves, len(tr_old_leaves), tr_cons_hashes
            ))[1]
        )
    tr_proof_bytes = TrillianModel.inclusion_proof_bytes(tr_proof)
    tr_commit_bytes = TrillianModel.sth_bytes(tr_sth)

    # ---- immudb-model ----
    im_headers, im_entry_hashes, im_global_root = None, None, None
    im_commit_ms_val = 0.0

    def _im_build():
        nonlocal im_headers, im_entry_hashes, im_global_root
        im_headers, im_entry_hashes, im_global_root = ImmudbModel.build(events)
    _, im_commit_ms_val = timed_ms(_im_build)

    im_proof, im_proof_gen_ms = timed_ms(
        lambda: ImmudbModel.gen_inclusion_proof(im_entry_hashes, pivot)
    )

    im_verify_samples = []
    im_incl_samples = []
    for _ in range(repetitions):
        im_verify_samples.append(
            timed_ms(lambda: ImmudbModel.verify_alh_chain(im_headers))[1]
        )
        im_incl_samples.append(
            timed_ms(lambda: ImmudbModel.verify_inclusion_proof(
                events[pivot], pivot, im_proof, im_global_root
            ))[1]
        )
    im_proof_bytes = ImmudbModel.inclusion_proof_bytes(im_proof)
    im_commit_bytes = ImmudbModel.commitment_bytes(im_headers, im_global_root)

    return {
        "size": size,
        "workload": workload,
        "seed": seed,
        "repetitions": repetitions,
        # --- LedgerShield ---
        "ls_commit_ms": ls_commit_ms,
        "ls_proof_gen_ms": ls_proof_gen_ms,
        "ls_cons_gen_ms": ls_cons_gen_ms,
        "ls_proof_bytes": ls_proof_bytes,
        "ls_commit_bytes": ls_commit_bytes,
        **{f"ls_verify_{k}": v for k, v in summarize_samples(ls_verify_samples).items()},
        **{f"ls_incl_{k}": v for k, v in summarize_samples(ls_incl_samples).items()},
        **{f"ls_cons_{k}": v for k, v in summarize_samples(ls_cons_samples).items()},
        # --- Trillian-model ---
        "tr_commit_ms": tr_commit_ms_val,
        "tr_proof_gen_ms": tr_proof_gen_ms,
        "tr_cons_gen_ms": tr_cons_gen_ms,
        "tr_proof_bytes": tr_proof_bytes,
        "tr_commit_bytes": tr_commit_bytes,
        **{f"tr_verify_{k}": v for k, v in summarize_samples(tr_verify_samples).items()},
        **{f"tr_incl_{k}": v for k, v in summarize_samples(tr_incl_samples).items()},
        **{f"tr_cons_{k}": v for k, v in summarize_samples(tr_cons_samples).items()},
        # --- immudb-model ---
        "im_commit_ms": im_commit_ms_val,
        "im_proof_gen_ms": im_proof_gen_ms,
        "im_proof_bytes": im_proof_bytes,
        "im_commit_bytes": im_commit_bytes,
        **{f"im_verify_{k}": v for k, v in summarize_samples(im_verify_samples).items()},
        **{f"im_incl_{k}": v for k, v in summarize_samples(im_incl_samples).items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="calibrated")
    parser.add_argument("--run-id", default="head_to_head")
    args = parser.parse_args()
    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")

    rows = []
    for size in sizes:
        print(f"[architectural-model] N={size:,} ...", flush=True)
        row = benchmark_size(size, args.seed, args.repetitions, args.workload, registry, private_key_path)
        rows.append(row)
        # Quick console summary
        print(
            f"  LedgerShield  commit={row['ls_commit_ms']:.1f}ms  "
            f"incl_p50={row['ls_incl_p50_ms']:.4f}ms  proof={row['ls_proof_bytes']}B"
        )
        print(
            f"  Trillian-mdl  commit={row['tr_commit_ms']:.1f}ms  "
            f"incl_p50={row['tr_incl_p50_ms']:.4f}ms  proof={row['tr_proof_bytes']}B"
        )
        print(
            f"  immudb-mdl    commit={row['im_commit_ms']:.1f}ms  "
            f"incl_p50={row['im_incl_p50_ms']:.4f}ms  proof={row['im_proof_bytes']}B"
        )

    # Write CSV
    csv_path = os.path.join(results_dir, "head_to_head.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    # Write JSON
    json_path = os.path.join(results_dir, "head_to_head.json")
    write_json(json_path, {"config": vars(args), "rows": rows})

    print(json.dumps({"csv": csv_path, "json": json_path}, indent=2))


if __name__ == "__main__":
    main()
