import argparse
import multiprocessing as mp
import os
import time
from typing import Dict

from common import generate_events, read_events_jsonl, write_json
from malicious_writer import (
    PolicyCheckpoint,
    PolicySigner,
    QuorumWitness,
    WitnessCertificate,
    make_conflicting_checkpoint,
    verify_quorum,
)
from merkle_signed_log import KeyRegistry, MerkleSignedLog


def _ms(start: float, end: float) -> float:
    return (end - start) * 1000.0


def _load_events(path: str, num_events: int):
    if path and os.path.exists(path):
        return read_events_jsonl(path, limit=num_events)
    return generate_events(num_events, 42, "calibrated")


def _clean_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    for name in os.listdir(path):
        child = os.path.join(path, name)
        if os.path.isfile(child):
            os.remove(child)


def _sign_worker(
    witness_id: str,
    key_dir: str,
    state_dir: str,
    checkpoint_payload: Dict,
    out_queue,
) -> None:
    try:
        witness = QuorumWitness.create(witness_id, key_dir, state_dir)
        checkpoint = PolicyCheckpoint.from_dict(checkpoint_payload)
        start = time.perf_counter()
        certificate = witness.sign_checkpoint(checkpoint)
        elapsed_ms = _ms(start, time.perf_counter())
        out_queue.put(
            {
                "status": "signed",
                "witness_id": witness_id,
                "certificate": certificate.to_dict(),
                "elapsed_ms": elapsed_ms,
                "pid": os.getpid(),
                "public_key_path": witness.public_key_path,
                "state_path": witness.state_path,
            }
        )
    except Exception as exc:
        out_queue.put(
            {
                "status": "error",
                "witness_id": witness_id,
                "error": str(exc),
                "pid": os.getpid(),
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a multi-process, independently keyed witness quorum demo."
    )
    parser.add_argument("--events-jsonl", default="data/berka/events.jsonl")
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--run-id", default="multiprocess_witness_demo")
    parser.add_argument("--quorum-size", type=int, default=5)
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()

    results_dir = os.path.join("results", args.run_id)
    key_dir = os.path.join(results_dir, "keys")
    witness_key_dir = os.path.join(results_dir, "witness_keys")
    witness_state_dir = os.path.join(results_dir, "witness_state")
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(witness_key_dir, exist_ok=True)
    os.makedirs(witness_state_dir, exist_ok=True)
    _clean_dir(witness_state_dir)

    registry = KeyRegistry.init_or_load(os.path.join(results_dir, "key_registry.json"), key_dir)
    private_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    events = _load_events(args.events_jsonl, args.num_events)
    commitment = MerkleSignedLog.commit(events, private_path, registry.active_key_id)

    signer = PolicySigner(private_path, registry.active_key_id, os.path.join(results_dir, "policy_state.json"))
    if os.path.exists(signer.state_path):
        os.remove(signer.state_path)
    checkpoint = signer.sign(commitment)

    queue = mp.Queue()
    processes = []
    start = time.perf_counter()
    for i in range(args.quorum_size):
        witness_id = f"w{i + 1}"
        process = mp.Process(
            target=_sign_worker,
            args=(witness_id, witness_key_dir, witness_state_dir, checkpoint.to_dict(), queue),
        )
        process.start()
        processes.append(process)

    worker_results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(timeout=10)
    wall_ms = _ms(start, time.perf_counter())

    signed = [r for r in worker_results if r["status"] == "signed"]
    public_keys = {r["witness_id"]: r["public_key_path"] for r in signed}
    certificates = [WitnessCertificate(**r["certificate"]) for r in signed]
    quorum_valid = verify_quorum(checkpoint, certificates[: args.threshold], public_keys, args.threshold)

    conflict_queue = mp.Queue()
    conflict = make_conflicting_checkpoint(checkpoint, "f" * 64)
    conflict_process = mp.Process(
        target=_sign_worker,
        args=("w1", witness_key_dir, witness_state_dir, conflict.to_dict(), conflict_queue),
    )
    conflict_process.start()
    conflict_result = conflict_queue.get(timeout=30)
    conflict_process.join(timeout=10)
    conflict_rejected = (
        conflict_result["status"] == "error"
        and "conflicting checkpoint" in conflict_result.get("error", "")
    )

    output = {
        "input": {
            "events_jsonl": args.events_jsonl if os.path.exists(args.events_jsonl) else "generated_calibrated",
            "num_events": len(events),
            "quorum_size": args.quorum_size,
            "threshold": args.threshold,
        },
        "checkpoint": checkpoint.to_dict(),
        "worker_results": worker_results,
        "signed_count": len(signed),
        "distinct_processes": len({r.get("pid") for r in worker_results}),
        "wall_latency_ms": wall_ms,
        "quorum_valid": quorum_valid,
        "threshold_certificates_verified": args.threshold,
        "conflict_result": conflict_result,
        "conflict_rejected": conflict_rejected,
        "interpretation": (
            "Local multi-process demo: each witness has a separate key and state file "
            "and runs in a separate OS process. This demonstrates process separation "
            "and certificate verification, not independent organizational governance."
        ),
    }
    out_path = os.path.join(results_dir, "multiprocess_witness_demo.json")
    write_json(out_path, output)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
