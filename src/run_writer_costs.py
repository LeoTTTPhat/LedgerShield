import argparse
import csv
import hashlib
import json
import math
import os
import resource
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import Event, generate_events, read_events_jsonl, write_json
from merkle_signed_log import (
    KeyRegistry,
    MerkleSignedLog,
    _commitment_message,
    _event_leaf,
    _hash_pair,
)


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


def mean(values: List[float]) -> float:
    return statistics.mean(values) if values else 0.0


def std(values: List[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def ci95(values: List[float]) -> float:
    return 1.96 * std(values) / math.sqrt(len(values)) if len(values) > 1 else 0.0


def summarize(values: List[float]) -> Dict[str, float]:
    return {
        "mean": mean(values),
        "std": std(values),
        "ci95": ci95(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
    }


def rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


class StreamingMerkleWriter:
    """Incremental RFC-6962-shaped Merkle writer.

    The frontier stores complete subtree roots by height.  To compute the
    current RFC-6962 root, the non-empty frontier entries are folded from
    low to high height: lower-height trees form the right suffix of the
    log, while higher-height trees remain to the left.
    """

    def __init__(self) -> None:
        self.size = 0
        self.frontier: List[Optional[str]] = []

    def append(self, event: Event) -> str:
        node = _event_leaf(event)
        level = 0
        while level < len(self.frontier) and self.frontier[level] is not None:
            node = _hash_pair(self.frontier[level], node)
            self.frontier[level] = None
            level += 1
        if level == len(self.frontier):
            self.frontier.append(node)
        else:
            self.frontier[level] = node
        self.size += 1
        return node

    def root_hash(self) -> str:
        roots = [h for h in self.frontier if h is not None]
        if not roots:
            return hashlib.sha256(b"\x02").hexdigest()
        cur = roots[0]
        for root in roots[1:]:
            cur = _hash_pair(root, cur)
        return cur

    def retained_frontier_hashes(self) -> int:
        return sum(1 for h in self.frontier if h is not None)


@dataclass(frozen=True)
class Policy:
    kind: str
    value: int

    @property
    def name(self) -> str:
        if self.kind == "events" and self.value == 1:
            return "per_event"
        if self.kind == "events":
            return f"per_{self.value}_events"
        return f"time_{self.value}s"

    def should_checkpoint(self, event: Event, count: int, last_checkpoint_ts: Optional[int]) -> bool:
        if self.kind == "events":
            return count % self.value == 0
        if last_checkpoint_ts is None:
            return True
        return event.timestamp - last_checkpoint_ts >= self.value


def parse_policies(batch_sizes: str, time_windows: str) -> List[Policy]:
    policies: List[Policy] = []
    for raw in batch_sizes.split(","):
        raw = raw.strip()
        if raw:
            value = int(raw)
            if value <= 0:
                raise ValueError("batch sizes must be positive")
            policies.append(Policy("events", value))
    for raw in time_windows.split(","):
        raw = raw.strip()
        if raw:
            value = int(raw)
            if value <= 0:
                raise ValueError("time windows must be positive seconds")
            policies.append(Policy("time", value))
    return policies


def proof_sample_sizes(checkpoints: List[int], max_samples: int) -> List[int]:
    if not checkpoints or max_samples <= 0:
        return []
    if len(checkpoints) <= max_samples:
        return checkpoints
    out = []
    for i in range(max_samples):
        idx = round(i * (len(checkpoints) - 1) / max(1, max_samples - 1))
        out.append(checkpoints[idx])
    return sorted(set(out))


def sign_checkpoint(private_key: Ed25519PrivateKey, root_hash: str, size: int, key_id: str) -> str:
    return private_key.sign(_commitment_message(root_hash, size, key_id)).hex()


def run_once(
    events: List[Event],
    policy: Policy,
    private_key: Ed25519PrivateKey,
    key_id: str,
    proof_samples: int,
) -> Dict:
    writer = StreamingMerkleWriter()
    append_us: List[float] = []
    sign_ms: List[float] = []
    checkpoint_sizes: List[int] = []
    checkpoint_gaps: List[int] = []
    last_checkpoint_size = 0
    last_checkpoint_ts: Optional[int] = None

    tracemalloc.start()
    for event in events:
        _, elapsed_ms = timed_ms(lambda e=event: writer.append(e))
        append_us.append(elapsed_ms * 1000.0)
        if policy.should_checkpoint(event, writer.size, last_checkpoint_ts):
            root = writer.root_hash()
            _, elapsed = timed_ms(
                lambda r=root, s=writer.size: sign_checkpoint(private_key, r, s, key_id)
            )
            sign_ms.append(elapsed)
            checkpoint_sizes.append(writer.size)
            checkpoint_gaps.append(writer.size - last_checkpoint_size)
            last_checkpoint_size = writer.size
            last_checkpoint_ts = event.timestamp

    if not checkpoint_sizes or checkpoint_sizes[-1] != writer.size:
        root = writer.root_hash()
        _, elapsed = timed_ms(lambda r=root, s=writer.size: sign_checkpoint(private_key, r, s, key_id))
        sign_ms.append(elapsed)
        checkpoint_sizes.append(writer.size)
        checkpoint_gaps.append(writer.size - last_checkpoint_size)

    proof_ms: List[float] = []
    proof_sizes: List[int] = []
    for size in proof_sample_sizes(checkpoint_sizes, proof_samples):
        prefix = events[:size]
        pivot = max(0, size // 2)
        proof, elapsed = timed_ms(lambda p=prefix, i=pivot: MerkleSignedLog.gen_inclusion_proof(p, i))
        proof_ms.append(elapsed)
        proof_sizes.append(len(json.dumps(proof).encode("utf-8")))

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "events": len(events),
        "policy": policy.name,
        "checkpoint_count": len(checkpoint_sizes),
        "checkpoint_gap_mean_events": mean(checkpoint_gaps),
        "checkpoint_gap_max_events": max(checkpoint_gaps) if checkpoint_gaps else 0,
        "append_mean_us": mean(append_us),
        "append_p95_us": percentile(append_us, 95),
        "checkpoint_sign_mean_ms": mean(sign_ms),
        "checkpoint_sign_p95_ms": percentile(sign_ms, 95),
        "checkpoint_sign_total_ms": sum(sign_ms),
        "proof_samples": len(proof_ms),
        "proof_gen_mean_ms": mean(proof_ms),
        "proof_gen_p95_ms": percentile(proof_ms, 95),
        "proof_size_mean_bytes": mean(proof_sizes),
        "frontier_hashes": writer.retained_frontier_hashes(),
        "tracemalloc_current_mb": current_bytes / (1024.0 * 1024.0),
        "tracemalloc_peak_mb": peak_bytes / (1024.0 * 1024.0),
        "process_max_rss_mb": rss_mb(),
    }


def aggregate_rows(rows: List[Dict]) -> List[Dict]:
    grouped: Dict[Tuple[int, str], List[Dict]] = {}
    for row in rows:
        grouped.setdefault((row["events"], row["policy"]), []).append(row)

    aggregate = []
    metric_fields = [
        "checkpoint_count",
        "checkpoint_gap_mean_events",
        "checkpoint_gap_max_events",
        "append_mean_us",
        "append_p95_us",
        "checkpoint_sign_mean_ms",
        "checkpoint_sign_p95_ms",
        "checkpoint_sign_total_ms",
        "proof_gen_mean_ms",
        "proof_gen_p95_ms",
        "proof_size_mean_bytes",
        "frontier_hashes",
        "tracemalloc_peak_mb",
        "process_max_rss_mb",
    ]
    for (events, policy), reps in sorted(grouped.items()):
        out = {
            "events": events,
            "policy": policy,
            "repetitions": len(reps),
            "proof_samples_per_rep": reps[0]["proof_samples"],
        }
        for field in metric_fields:
            values = [float(r[field]) for r in reps]
            stats = summarize(values)
            out[f"{field}_mean"] = stats["mean"]
            out[f"{field}_std"] = stats["std"]
            out[f"{field}_ci95"] = stats["ci95"]
        aggregate.append(out)
    return aggregate


def load_events(args, size: int, seed: int) -> List[Event]:
    if args.events_jsonl:
        return read_events_jsonl(args.events_jsonl, limit=size)
    return generate_events(size, seed, args.workload)


def self_check(events: List[Event]) -> None:
    if not events:
        return
    writer = StreamingMerkleWriter()
    for event in events:
        writer.append(event)
    reference = MerkleSignedLog.leaves(events)
    # Compare against the public full-tree code without signing.
    proof = MerkleSignedLog.gen_inclusion_proof(events, len(events) // 2)
    if not MerkleSignedLog.verify_inclusion_proof(
        events[len(events) // 2],
        len(events) // 2,
        proof,
        writer.root_hash(),
    ):
        raise RuntimeError("streaming writer root does not match inclusion verifier")
    if len(reference) != writer.size:
        raise RuntimeError("streaming writer lost events")


def write_csv(path: str, rows: List[Dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--batch-sizes", default="1,256,10000")
    parser.add_argument("--time-windows", default="60")
    parser.add_argument("--proof-samples", type=int, default=4)
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="calibrated")
    parser.add_argument("--events-jsonl", default="")
    parser.add_argument("--run-id", default="writer_costs")
    args = parser.parse_args()

    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    policies = parse_policies(args.batch_sizes, args.time_windows)
    if not sizes or not policies or args.repetitions <= 0:
        raise ValueError("sizes, policies and repetitions must be non-empty")

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")

    sample_events = load_events(args, min(sizes[0], 257), args.seed)
    self_check(sample_events)

    rows: List[Dict] = []
    for size in sizes:
        for rep in range(args.repetitions):
            events = load_events(args, size, args.seed + rep)
            if len(events) != size:
                raise ValueError(f"requested {size} events but loaded {len(events)}")
            for policy in policies:
                row = run_once(events, policy, private_key, registry.active_key_id, args.proof_samples)
                row["seed"] = args.seed + rep
                row["rep"] = rep + 1
                row["workload"] = "jsonl" if args.events_jsonl else args.workload
                rows.append(row)
                print(
                    f"{size} {policy.name} rep={rep + 1}: "
                    f"checkpoints={row['checkpoint_count']} "
                    f"append={row['append_mean_us']:.3f}us "
                    f"sign={row['checkpoint_sign_mean_ms']:.4f}ms "
                    f"proof={row['proof_gen_mean_ms']:.3f}ms "
                    f"peak={row['tracemalloc_peak_mb']:.2f}MiB",
                    flush=True,
                )

    aggregate = aggregate_rows(rows)
    raw_csv = os.path.join(results_dir, "writer_costs_raw.csv")
    aggregate_csv = os.path.join(results_dir, "writer_costs_aggregate.csv")
    json_path = os.path.join(results_dir, "writer_costs.json")
    write_csv(raw_csv, rows)
    write_csv(aggregate_csv, aggregate)
    write_json(
        json_path,
        {
            "workload": "jsonl" if args.events_jsonl else args.workload,
            "events_jsonl": args.events_jsonl,
            "seed": args.seed,
            "repetitions": args.repetitions,
            "sizes": sizes,
            "policies": [p.name for p in policies],
            "proof_samples_per_policy_rep": args.proof_samples,
            "notes": [
                "Append uses canonical JSON, leaf hashing and streaming frontier updates.",
                "Checkpoint signing signs the same canonical (root_hash, tree_size, key_id) payload as LedgerShield commitments.",
                "Inclusion proof generation samples current artifact proof generation at checkpoint sizes; it is not performed for every event unless explicitly sampled.",
                "tracemalloc_peak_mb measures Python allocations during a single policy run; process_max_rss_mb is the process high-water mark.",
            ],
            "raw_rows": rows,
            "aggregate_rows": aggregate,
        },
    )
    print(
        json.dumps(
            {
                "writer_costs_raw_csv": raw_csv,
                "writer_costs_aggregate_csv": aggregate_csv,
                "writer_costs_json": json_path,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
