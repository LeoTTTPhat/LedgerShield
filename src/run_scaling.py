import argparse
import csv
import json
import os
import time
from typing import Dict, List

from common import generate_events, write_json
from merkle_signed_log import KeyRegistry, MerkleSignedLog
from witness_anchor import WitnessAnchorLog


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


def summarize(samples: List[float]) -> Dict[str, float]:
    return {
        "p50_ms": percentile(samples, 50),
        "p95_ms": percentile(samples, 95),
        "p99_ms": percentile(samples, 99),
        "mean_ms": sum(samples) / max(1, len(samples)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--run-id", default="scaling")
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="synthetic")
    args = parser.parse_args()
    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    if not sizes or args.repetitions <= 0:
        raise ValueError("--sizes and --repetitions must be non-empty")

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")

    rows = []
    for size in sizes:
        events = generate_events(size, args.seed, args.workload)
        old_events = events[: max(1, size // 2)]
        commit, commit_ms = timed_ms(
            lambda: MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
        )
        proof, proof_gen_ms = timed_ms(lambda: MerkleSignedLog.gen_inclusion_proof(events, size // 2))
        consistency, consistency_gen_ms = timed_ms(
            lambda: MerkleSignedLog.gen_consistency_proof(old_events, events, private_key_path, registry.active_key_id)
        )
        witness = WitnessAnchorLog(os.path.join(results_dir, f"witness_{size}.jsonl"))
        _, anchor_ms = timed_ms(lambda: witness.append(commit, timestamp=1700000000 + size))

        verify_samples = []
        inclusion_samples = []
        consistency_samples = []
        anchor_samples = []
        for _ in range(args.repetitions):
            verify_samples.append(timed_ms(lambda: MerkleSignedLog.verify(events, commit, registry))[1])
            inclusion_samples.append(
                timed_ms(lambda: MerkleSignedLog.verify_inclusion_proof(events[size // 2], size // 2, proof, commit.root_hash))[1]
            )
            consistency_samples.append(
                timed_ms(lambda: MerkleSignedLog.verify_consistency_proof_external(consistency, registry))[1]
            )
            anchor_samples.append(timed_ms(lambda: witness.detect_rollback(commit))[1])

        row = {
            "size": size,
            "commit_ms": commit_ms,
            "proof_gen_ms": proof_gen_ms,
            "consistency_gen_ms": consistency_gen_ms,
            "anchor_append_ms": anchor_ms,
            "proof_size_bytes": len(json.dumps(proof).encode("utf-8")),
            "consistency_proof_hashes": len(consistency["proof_hashes"]),
            "commitment_size_bytes": len(json.dumps(commit.to_dict(), sort_keys=True).encode("utf-8")),
            **{f"full_verify_{k}": v for k, v in summarize(verify_samples).items()},
            **{f"inclusion_verify_{k}": v for k, v in summarize(inclusion_samples).items()},
            **{f"consistency_verify_{k}": v for k, v in summarize(consistency_samples).items()},
            **{f"anchor_check_{k}": v for k, v in summarize(anchor_samples).items()},
        }
        rows.append(row)

    csv_path = os.path.join(results_dir, "scaling_results.csv")
    json_path = os.path.join(results_dir, "scaling_results.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    write_json(
        json_path,
        {
            "workload": args.workload,
            "seed": args.seed,
            "repetitions": args.repetitions,
            "rows": rows,
        },
    )
    print(json.dumps({"scaling_csv": csv_path, "scaling_json": json_path}, indent=2))


if __name__ == "__main__":
    main()
