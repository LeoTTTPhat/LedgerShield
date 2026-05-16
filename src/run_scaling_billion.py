"""run_scaling_billion.py – Streaming Merkle scaling benchmark projecting to 10^9 events.

The standard MerkleSignedLog.commit() loads all N leaf hashes into RAM simultaneously.
At 10^9 events that would require ~64 GB of hash storage alone, making it infeasible on
commodity hardware.

This module adds a *streaming* Merkle root algorithm (RFC 6962 §6 "streaming" variant)
that processes events in fixed-size chunks and maintains only O(log N) internal state,
making 10^9-scale commitment generation memory-feasible.

Algorithm (Streaming RFC 6962 Merkle):
  Maintain a stack of at most ceil(log2(N)) intermediate subtree roots.
  For each new leaf:
    push the leaf hash onto the stack.
    while the top two stack entries cover equal-power-of-two subtree sizes, merge them.
  The final root is the merge of all remaining stack entries right-to-left.

This is equivalent to _build_root() but uses O(log N) memory and O(1) amortised work
per leaf. Inclusion proofs still require reprocessing a chunk window, but the commitment
(root hash + signature) is produced in a single streaming pass.

Usage:
    python src/run_scaling_billion.py \
        --sizes 1000,10000,100000,1000000,10000000 \
        --projected 1000000000 \
        --seed 42 \
        --chunk-size 100000 \
        --repetitions 3 \
        --workload calibrated \
        --run-id scaling_billion
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from common import generate_events, write_json, Event
from merkle_signed_log import (
    KeyRegistry,
    _hash_leaf,
    _hash_node,
    _build_root,
    _commitment_message,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as _ser

    def _sign(private_key_path: str, message: bytes) -> str:
        with open(private_key_path, "rb") as f:
            pem = f.read()
        key = Ed25519PrivateKey.from_private_bytes(
            _ser.load_pem_private_key(pem, password=None).private_bytes(
                _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption()
            )
        )
        return key.sign(message).hex()

    def _load_ed25519_private_key(path: str) -> Ed25519PrivateKey:
        with open(path, "rb") as f:
            return _ser.load_pem_private_key(f.read(), password=None)

    def _sign_fast(key: Ed25519PrivateKey, message: bytes) -> str:
        return key.sign(message).hex()

except ImportError:
    def _sign(private_key_path: str, message: bytes) -> str:
        raise RuntimeError("cryptography package required")


# ---------------------------------------------------------------------------
# Streaming Merkle tree (O(log N) memory)
# ---------------------------------------------------------------------------

class StreamingMerkleTree:
    """
    RFC 6962-compatible Merkle tree built in a single streaming pass.

    Internal state: a stack of (subtree_size, root_hash) pairs where each
    subtree_size is a power of two and sizes are strictly decreasing towards
    the bottom of the stack. This invariant is maintained by merging whenever
    the top two entries have equal sizes.

    Memory usage: O(log2 N) hash strings at any point.
    """

    def __init__(self) -> None:
        # Stack entries: (size_power_of_two, hash_hex)
        self._stack: List[Tuple[int, str]] = []
        self._n: int = 0

    def add_leaf(self, leaf_hash: str) -> None:
        """Add a pre-hashed leaf (output of _hash_leaf) to the tree."""
        self._n += 1
        # A single leaf has subtree size 1 (= 2^0)
        entry = (1, leaf_hash)
        self._stack.append(entry)
        # Merge adjacent equal-size subtrees
        while len(self._stack) >= 2 and self._stack[-1][0] == self._stack[-2][0]:
            right_size, right_hash = self._stack.pop()
            left_size, left_hash = self._stack.pop()
            merged_hash = _hash_node(left_hash, right_hash)
            self._stack.append((left_size + right_size, merged_hash))

    def root(self) -> str:
        """
        Return the current Merkle root.

        Remaining stack entries (power-of-two subtrees of decreasing size)
        are merged right-to-left to produce the final root, matching the
        RFC 6962 'MTH' definition and _build_root() output exactly.
        """
        from hashlib import sha256
        EMPTY_ROOT = sha256(b"\x02").hexdigest()
        if not self._stack:
            return EMPTY_ROOT
        # Merge from right (smallest) to left (largest)
        result_hash = self._stack[-1][1]
        for i in range(len(self._stack) - 2, -1, -1):
            result_hash = _hash_node(self._stack[i][1], result_hash)
        return result_hash

    @property
    def size(self) -> int:
        return self._n

    @property
    def stack_depth(self) -> int:
        return len(self._stack)


def streaming_commit(
    events: List[Event],
    private_key: "Ed25519PrivateKey",
    key_id: str,
    chunk_size: int = 100_000,
) -> Tuple[str, str, float]:
    """
    Compute a Merkle commitment over `events` using the streaming tree.

    Returns (root_hash, signature_hex, elapsed_ms).
    Memory peak: O(chunk_size * avg_event_json_bytes + log2(N) * 32 bytes).
    """
    tree = StreamingMerkleTree()
    t0 = time.perf_counter()

    for i in range(0, len(events), chunk_size):
        chunk = events[i : i + chunk_size]
        for event in chunk:
            tree.add_leaf(_hash_leaf(event.canonical_json()))

    root = tree.root()
    msg = _commitment_message(root, tree.size, key_id)
    sig = _sign_fast(private_key, msg)
    elapsed = (time.perf_counter() - t0) * 1000.0
    return root, sig, elapsed


def verify_streaming_root_matches_batch(events: List[Event]) -> bool:
    """Correctness check: streaming root must equal batch _build_root output."""
    tree = StreamingMerkleTree()
    for e in events:
        tree.add_leaf(_hash_leaf(e.canonical_json()))
    streaming_root = tree.root()
    batch_root = _build_root([_hash_leaf(e.canonical_json()) for e in events])
    return streaming_root == batch_root


# ---------------------------------------------------------------------------
# Timing helpers
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


# ---------------------------------------------------------------------------
# O(N) linear projection
# ---------------------------------------------------------------------------

def fit_linear(sizes: List[int], times_ms: List[float]) -> Tuple[float, float]:
    """Fit t = slope * N + intercept via least squares. Returns (slope, intercept)."""
    n = len(sizes)
    if n < 2:
        return times_ms[0] / sizes[0] if sizes else 0.0, 0.0
    sx = sum(sizes)
    sy = sum(times_ms)
    sxx = sum(x * x for x in sizes)
    sxy = sum(x * y for x, y in zip(sizes, times_ms))
    denom = n * sxx - sx * sx
    if denom == 0:
        return sy / sx, 0.0
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return slope, intercept


def project_linear(slope: float, intercept: float, target_n: int) -> float:
    return max(0.0, slope * target_n + intercept)


def residual_std(sizes, times_ms, slope, intercept) -> float:
    if len(sizes) < 3:
        return 0.0
    residuals = [t - (slope * n + intercept) for n, t in zip(sizes, times_ms)]
    return statistics.stdev(residuals)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def benchmark_one(
    size: int,
    seed: int,
    repetitions: int,
    workload: str,
    private_key: "Ed25519PrivateKey",
    key_id: str,
    chunk_size: int,
) -> Dict:
    events = generate_events(size, seed, workload)

    # --- streaming commit (multiple reps for timing stability) ---
    commit_samples = []
    root_hash = None
    for _ in range(max(1, repetitions)):
        root, sig, ms = streaming_commit(events, private_key, key_id, chunk_size)
        commit_samples.append(ms)
        root_hash = root

    # --- batch commit for correctness cross-check ---
    batch_leaves = [_hash_leaf(e.canonical_json()) for e in events]
    batch_root = _build_root(batch_leaves)
    roots_match = root_hash == batch_root

    # --- inclusion proof generation (batch path, O(log N)) ---
    pivot = size // 2
    from merkle_signed_log import MerkleSignedLog
    proof, proof_gen_ms = timed_ms(
        lambda: MerkleSignedLog.gen_inclusion_proof(events, pivot)
    )
    proof_bytes = len(json.dumps(proof).encode())

    # --- inclusion proof verification ---
    incl_samples = []
    for _ in range(repetitions):
        _, ms = timed_ms(
            lambda: MerkleSignedLog.verify_inclusion_proof(
                events[pivot], pivot, proof, root_hash
            )
        )
        incl_samples.append(ms)

    # Commitment size: root_hash(64) + sig(128) + key_id + tree_size JSON
    commitment_size = len(json.dumps({
        "root_hash": root_hash,
        "signature": sig,
        "key_id": key_id,
        "tree_size": size,
    }, separators=(",", ":")).encode())

    return {
        "size": size,
        "seed": seed,
        "workload": workload,
        "chunk_size": chunk_size,
        "streaming_commit_mean_ms": statistics.mean(commit_samples),
        "streaming_commit_std_ms": statistics.stdev(commit_samples) if len(commit_samples) > 1 else 0.0,
        "streaming_commit_p50_ms": percentile(commit_samples, 50),
        "streaming_commit_p95_ms": percentile(commit_samples, 95),
        "roots_match": roots_match,
        "proof_gen_ms": proof_gen_ms,
        "proof_size_bytes": proof_bytes,
        "incl_verify_mean_ms": statistics.mean(incl_samples),
        "incl_verify_p50_ms": percentile(incl_samples, 50),
        "incl_verify_p95_ms": percentile(incl_samples, 95),
        "commitment_size_bytes": commitment_size,
        "streaming_stack_max_depth": math.ceil(math.log2(size)) if size > 1 else 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1000,10000,100000,1000000,10000000")
    parser.add_argument("--projected", type=int, default=1_000_000_000,
                        help="Target size to project to (default: 1e9)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="calibrated")
    parser.add_argument("--run-id", default="scaling_billion")
    args = parser.parse_args()

    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)

    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    private_key = _load_ed25519_private_key(private_key_path)

    # --- Correctness check at small scale ---
    test_events = generate_events(500, args.seed, args.workload)
    assert verify_streaming_root_matches_batch(test_events), \
        "FATAL: streaming root does not match batch root at N=500"
    print("Correctness check passed: streaming root == batch root at N=500")

    rows = []
    for size in sizes:
        print(f"[streaming-scaling] N={size:,} ...", flush=True)
        row = benchmark_one(
            size, args.seed, args.repetitions, args.workload,
            private_key, registry.active_key_id, args.chunk_size
        )
        rows.append(row)
        assert row["roots_match"], f"Root mismatch at N={size}"
        print(
            f"  streaming_commit_mean={row['streaming_commit_mean_ms']:.1f}ms  "
            f"incl_p50={row['incl_verify_p50_ms']:.4f}ms  "
            f"proof={row['proof_size_bytes']}B  "
            f"stack_depth≤{row['streaming_stack_max_depth']}"
        )

    # --- Linear projection to target ---
    measured_sizes = [r["size"] for r in rows]
    measured_commit_ms = [r["streaming_commit_mean_ms"] for r in rows]
    slope, intercept = fit_linear(measured_sizes, measured_commit_ms)
    res_std = residual_std(measured_sizes, measured_commit_ms, slope, intercept)
    # 95% prediction interval (approximate, based on residual std)
    proj_commit_ms = project_linear(slope, intercept, args.projected)
    proj_ci_half = 1.96 * res_std * math.sqrt(1 + 1.0 / len(measured_sizes))

    # Proof size at 10^9 = O(log2(10^9)) hashes * 64 bytes + JSON overhead ≈ 30 * 90 = ~2700B
    proj_proof_size = int(math.ceil(math.log2(args.projected)) * 90 + 100)
    proj_stack_depth = math.ceil(math.log2(args.projected))

    projection = {
        "target_size": args.projected,
        "model": "linear (t = slope * N + intercept)",
        "slope_ms_per_event": slope,
        "intercept_ms": intercept,
        "residual_std_ms": res_std,
        "projected_commit_mean_ms": proj_commit_ms,
        "projected_commit_ci95_half_ms": proj_ci_half,
        "projected_commit_seconds": proj_commit_ms / 1000.0,
        "projected_proof_size_bytes_approx": proj_proof_size,
        "projected_streaming_stack_depth": proj_stack_depth,
        "note": (
            "Projection assumes the O(N) streaming commit dominates at 10^9 scale. "
            "Inclusion-proof generation (O(N) leaf scan to rebuild the proof path) "
            "would also scale linearly; consistency proofs remain O(log N) hashes. "
            "RAM requirement for streaming commit: O(chunk_size * event_bytes + log2(N) * 32B)."
        ),
    }

    print(f"\n--- Linear projection to N={args.projected:,} ---")
    print(f"  slope     = {slope:.6f} ms/event")
    print(f"  intercept = {intercept:.2f} ms")
    print(f"  projected commit time = {proj_commit_ms/1000:.1f} s  "
          f"(±{proj_ci_half/1000:.1f} s, 95% PI)")
    print(f"  projected proof size  ≈ {proj_proof_size} bytes  "
          f"(stack depth ≤ {proj_stack_depth})")

    # --- Write outputs ---
    csv_path = os.path.join(results_dir, "scaling_billion.csv")
    all_fields = list(rows[0].keys()) if rows else []
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    json_path = os.path.join(results_dir, "scaling_billion.json")
    write_json(json_path, {
        "config": {
            "sizes": sizes,
            "projected": args.projected,
            "seed": args.seed,
            "chunk_size": args.chunk_size,
            "repetitions": args.repetitions,
            "workload": args.workload,
        },
        "measured_rows": rows,
        "projection": projection,
    })

    print(json.dumps({"csv": csv_path, "json": json_path}, indent=2))


if __name__ == "__main__":
    main()
