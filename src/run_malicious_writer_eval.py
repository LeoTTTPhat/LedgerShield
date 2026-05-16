import argparse
import os
import statistics
import time
from typing import List

from common import Event, generate_events, read_events_jsonl, write_json
from malicious_writer import (
    PolicySigner,
    QuorumWitness,
    audit_completeness,
    make_conflicting_checkpoint,
    source_id_from_reference,
    verify_policy_checkpoint,
    verify_quorum,
)
from merkle_signed_log import KeyRegistry, MerkleSignedLog


def _ms(start: float, end: float) -> float:
    return (end - start) * 1000.0


def _mean(values: List[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _std(values: List[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _ci95(values: List[float]) -> float:
    if len(values) <= 1:
        return 0.0
    # Student-t critical value for n in {2..10}; normal approximation above.
    tcrit = {
        2: 12.706,
        3: 4.303,
        4: 3.182,
        5: 2.776,
        6: 2.571,
        7: 2.447,
        8: 2.365,
        9: 2.306,
        10: 2.262,
    }.get(len(values), 1.96)
    return tcrit * _std(values) / (len(values) ** 0.5)


def _summary(values: List[float]) -> dict:
    return {
        "mean_ms": _mean(values),
        "std_ms": _std(values),
        "ci95_ms": _ci95(values),
        "samples_ms": values,
    }


def load_events(path: str, num_events: int) -> List[Event]:
    if path and os.path.exists(path):
        return read_events_jsonl(path, limit=num_events)
    return generate_events(num_events, 42, "calibrated")


def _reset_state(policy_state_path: str, witness_state_dir: str) -> None:
    if os.path.exists(policy_state_path):
        os.remove(policy_state_path)
    if os.path.isdir(witness_state_dir):
        for filename in os.listdir(witness_state_dir):
            path = os.path.join(witness_state_dir, filename)
            if os.path.isfile(path):
                os.remove(path)


def run_once(args: argparse.Namespace, events: List[Event], repetition: int) -> dict:
    results_dir = os.path.join("results", args.run_id)
    rep_dir = os.path.join(results_dir, f"rep_{repetition:02d}")
    key_dir = os.path.join(rep_dir, "keys")
    witness_key_dir = os.path.join(rep_dir, "witness_keys")
    witness_state_dir = os.path.join(rep_dir, "witness_state")
    os.makedirs(rep_dir, exist_ok=True)
    policy_state_path = os.path.join(rep_dir, "policy_state.json")
    _reset_state(policy_state_path, witness_state_dir)

    registry_path = os.path.join(rep_dir, "key_registry.json")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    signer = PolicySigner(private_path, registry.active_key_id, policy_state_path)

    checkpoints = []
    policy_latencies = []
    prefix_sizes = sorted(
        {max(1, len(events) // 4), max(1, len(events) // 2), max(1, 3 * len(events) // 4), len(events)}
    )
    for size in prefix_sizes:
        commitment = MerkleSignedLog.commit(events[:size], private_path, registry.active_key_id)
        start = time.perf_counter()
        checkpoint = signer.sign(commitment)
        end = time.perf_counter()
        if not verify_policy_checkpoint(checkpoint, registry):
            raise RuntimeError("policy checkpoint failed signature verification")
        policy_latencies.append(_ms(start, end))
        checkpoints.append(checkpoint)

    duplicate_sequence_rejected = False
    try:
        signer.sign(MerkleSignedLog.commit(events, private_path, registry.active_key_id), sequence=checkpoints[-1].sequence)
    except ValueError:
        duplicate_sequence_rejected = True

    decreasing_size_rejected = False
    try:
        smaller_size = max(1, checkpoints[-1].tree_size - 1)
        signer.sign(MerkleSignedLog.commit(events[:smaller_size], private_path, registry.active_key_id))
    except ValueError:
        decreasing_size_rejected = True

    witnesses = [
        QuorumWitness.create(f"w{i + 1}", witness_key_dir, witness_state_dir)
        for i in range(args.quorum_size)
    ]
    latest = checkpoints[-1]
    start = time.perf_counter()
    certificates = [witness.sign_checkpoint(latest) for witness in witnesses[: args.threshold]]
    quorum_valid = verify_quorum(
        latest,
        certificates,
        {witness.witness_id: witness.public_key_path for witness in witnesses},
        args.threshold,
    )
    end = time.perf_counter()
    quorum_latency_ms = _ms(start, end)

    conflict_rejected = False
    try:
        witnesses[0].sign_checkpoint(make_conflicting_checkpoint(latest, "e" * 64))
    except ValueError:
        conflict_rejected = True

    expected_source_ids = [source_id_from_reference(event) for event in events]
    omit_index = len(events) // 2
    omitted_events = events[:omit_index] + events[omit_index + 1 :]
    start = time.perf_counter()
    completeness_report = audit_completeness(omitted_events, expected_source_ids)
    end_completeness = time.perf_counter()
    complete_report = audit_completeness(events, expected_source_ids)

    return {
        "policy_mean_sign_latency_ms": _mean(policy_latencies),
        "policy_sign_latency_ms": policy_latencies,
        "checkpoints_signed": len(checkpoints),
        "decreasing_size_rejected": decreasing_size_rejected,
        "duplicate_sequence_rejected": duplicate_sequence_rejected,
        "quorum_latency_ms": quorum_latency_ms,
        "certificates": len(certificates),
        "conflict_rejected": conflict_rejected,
        "quorum_valid": quorum_valid,
        "audit_latency_ms": _ms(start, end_completeness),
        "complete_trace_accepted": complete_report["complete"],
        "expected_count": completeness_report["expected_count"],
        "missing_count": len(completeness_report["missing_ids"]),
        "omission_detected": not completeness_report["complete"],
        "sample_missing_ids": completeness_report["missing_ids"][:5],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate malicious-writer extension controls.")
    parser.add_argument("--events-jsonl", default="data/berka/events.jsonl")
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--run-id", default="malicious_writer_eval")
    parser.add_argument("--quorum-size", type=int, default=5)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)

    events = load_events(args.events_jsonl, args.num_events)
    if not events:
        raise ValueError("no events available for malicious-writer evaluation")

    repetitions = [run_once(args, events, i + 1) for i in range(args.repetitions)]
    latest = repetitions[-1]
    policy_means = [r["policy_mean_sign_latency_ms"] for r in repetitions]
    quorum_latencies = [r["quorum_latency_ms"] for r in repetitions]
    audit_latencies = [r["audit_latency_ms"] for r in repetitions]

    output = {
        "input": {
            "events_jsonl": args.events_jsonl if os.path.exists(args.events_jsonl) else "generated_calibrated",
            "num_events": len(events),
            "repetitions": args.repetitions,
            "workload_note": "Berka is real anonymized historical bank data when data/berka/events.jsonl is present.",
        },
        "policy_signer_monotonicity": {
            "checkpoints_signed": latest["checkpoints_signed"],
            "decreasing_size_rejected": all(r["decreasing_size_rejected"] for r in repetitions),
            "duplicate_sequence_rejected": all(r["duplicate_sequence_rejected"] for r in repetitions),
            "mean_sign_latency_ms": _mean(policy_means),
            "std_sign_latency_ms": _std(policy_means),
            "ci95_sign_latency_ms": _ci95(policy_means),
            "sign_latency_ms": latest["policy_sign_latency_ms"],
            "repetition_summary": _summary(policy_means),
        },
        "quorum_witness_certificates": {
            "certificates": latest["certificates"],
            "conflict_rejected": all(r["conflict_rejected"] for r in repetitions),
            "quorum_size": args.quorum_size,
            "quorum_valid": all(r["quorum_valid"] for r in repetitions),
            "threshold": args.threshold,
            "verify_and_sign_latency_ms": _mean(quorum_latencies),
            "std_verify_and_sign_latency_ms": _std(quorum_latencies),
            "ci95_verify_and_sign_latency_ms": _ci95(quorum_latencies),
            "repetition_summary": _summary(quorum_latencies),
        },
        "completeness_source_auditing": {
            "audit_latency_ms": _mean(audit_latencies),
            "std_audit_latency_ms": _std(audit_latencies),
            "ci95_audit_latency_ms": _ci95(audit_latencies),
            "complete_trace_accepted": all(r["complete_trace_accepted"] for r in repetitions),
            "expected_count": latest["expected_count"],
            "missing_count": latest["missing_count"],
            "omission_detected": all(r["omission_detected"] for r in repetitions),
            "sample_missing_ids": latest["sample_missing_ids"],
            "repetition_summary": _summary(audit_latencies),
        },
        "repetitions": repetitions,
    }
    write_json(os.path.join(results_dir, "malicious_writer_eval.json"), output)
    print(f"wrote {os.path.join(results_dir, 'malicious_writer_eval.json')}")


if __name__ == "__main__":
    main()
