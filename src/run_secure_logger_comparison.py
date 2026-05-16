import argparse
import csv
import hashlib
import hmac
import json
import os
import platform
import statistics
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from attacks import AttackSuite
from common import Event, generate_events, read_events_jsonl, sha256_hex, write_json
from merkle_signed_log import KeyRegistry, MerkleSignedLog


AttackFn = Callable[[List[Event], int], List[Event]]


@dataclass
class FSCommitment:
    mode: str
    event_count: int
    final_tag_hex: str
    batch_size: int


def _mean(values: List[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _std(values: List[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _ci95(values: List[float]) -> float:
    if len(values) <= 1:
        return 0.0
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


def _summary(values: List[float]) -> Dict:
    return {
        "mean": _mean(values),
        "std": _std(values),
        "ci95": _ci95(values),
        "samples": values,
    }


def _next_key(key: bytes) -> bytes:
    return hashlib.sha256(b"LedgerShield-fs-next-v1" + key).digest()


def _event_bytes(event: Event) -> bytes:
    return event.canonical_json().encode("utf-8")


class ForwardSecureHMACStream:
    """User-space model of a forward-secure per-event audit tag stream.

    This is not Nitro. It approximates the cryptographic envelope used by
    forward-secure/eBPF secure loggers: each event receives an HMAC under an
    evolving key, and old keys are conceptually erased by the collector.
    Reproducible verification keeps the initial seed key in the artifact.
    """

    @staticmethod
    def commit(events: List[Event], seed_key: bytes) -> FSCommitment:
        key = seed_key
        prev_tag = b"\x00" * 32
        for idx, event in enumerate(events, start=1):
            msg = idx.to_bytes(8, "big") + prev_tag + _event_bytes(event)
            prev_tag = hmac.new(key, msg, hashlib.sha256).digest()
            key = _next_key(key)
        return FSCommitment("fs_hmac_stream", len(events), prev_tag.hex(), 1)

    @staticmethod
    def verify(events: List[Event], commitment: FSCommitment, seed_key: bytes) -> Tuple[bool, int]:
        rebuilt = ForwardSecureHMACStream.commit(events, seed_key)
        return (
            rebuilt.event_count == commitment.event_count
            and hmac.compare_digest(rebuilt.final_tag_hex, commitment.final_tag_hex),
            40,
        )

    @staticmethod
    def verify_prefix(events: List[Event], commitment: FSCommitment, seed_key: bytes, index: int) -> Tuple[bool, int]:
        prefix = events[: index + 1]
        rebuilt = ForwardSecureHMACStream.commit(prefix, seed_key)
        return rebuilt.event_count == len(prefix), 40 * len(prefix)


class BatchReducedHMACStream:
    """Batch-reduced forward-secure model inspired by in-kernel log reduction.

    Each batch is compressed to one SHA-256 digest, then authenticated by an
    evolving HMAC key. This lowers cryptographic work at the cost of coarser
    event granularity. It is a local artifact model, not Nitro-R.
    """

    @staticmethod
    def commit(events: List[Event], seed_key: bytes, batch_size: int) -> FSCommitment:
        key = seed_key
        prev_tag = b"\x00" * 32
        for batch_no, start in enumerate(range(0, len(events), batch_size), start=1):
            batch = events[start : start + batch_size]
            digest = hashlib.sha256()
            for event in batch:
                data = _event_bytes(event)
                digest.update(len(data).to_bytes(8, "big"))
                digest.update(data)
            msg = batch_no.to_bytes(8, "big") + len(batch).to_bytes(4, "big") + prev_tag + digest.digest()
            prev_tag = hmac.new(key, msg, hashlib.sha256).digest()
            key = _next_key(key)
        return FSCommitment("batch_reduced_fs_hmac", len(events), prev_tag.hex(), batch_size)

    @staticmethod
    def verify(events: List[Event], commitment: FSCommitment, seed_key: bytes) -> Tuple[bool, int]:
        rebuilt = BatchReducedHMACStream.commit(events, seed_key, commitment.batch_size)
        return (
            rebuilt.event_count == commitment.event_count
            and hmac.compare_digest(rebuilt.final_tag_hex, commitment.final_tag_hex),
            40,
        )

    @staticmethod
    def verify_prefix(events: List[Event], seed_key: bytes, index: int, batch_size: int) -> Tuple[bool, int]:
        prefix_len = min(len(events), ((index // batch_size) + 1) * batch_size)
        BatchReducedHMACStream.commit(events[:prefix_len], seed_key, batch_size)
        return True, 40 * ((prefix_len + batch_size - 1) // batch_size)


def _time_ms(fn: Callable[[], object]) -> Tuple[object, float]:
    start = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - start) * 1000.0


def _load_events(args: argparse.Namespace) -> List[Event]:
    if args.events_jsonl and os.path.exists(args.events_jsonl):
        return read_events_jsonl(args.events_jsonl, args.num_events)
    return generate_events(args.num_events, args.seed, args.workload)


def _attack_detection_rate(
    events: List[Event],
    seed: int,
    verify_fn: Callable[[List[Event]], Tuple[bool, int]],
) -> float:
    attacks: Dict[str, AttackFn] = {
        "insert": AttackSuite.insert,
        "delete": AttackSuite.delete,
        "modify": AttackSuite.modify,
        "replay": AttackSuite.replay,
        "truncate": AttackSuite.truncate,
    }
    detected = 0
    for attack_name, attack_fn in attacks.items():
        attacked = attack_fn(events, seed)
        ok, _ = verify_fn(attacked)
        detected += 0 if ok else 1
    return detected / len(attacks)


def run_once(args: argparse.Namespace, events: List[Event], repetition: int) -> List[Dict]:
    rep_dir = os.path.join("results", args.run_id, f"rep_{repetition:02d}")
    key_dir = os.path.join(rep_dir, "keys")
    registry_path = os.path.join(rep_dir, "key_registry.json")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    seed_key = hashlib.sha256(f"{args.seed}:{repetition}:fs-model".encode("utf-8")).digest()
    pivot = len(events) // 2

    rows: List[Dict] = []

    commitment, build_ms = _time_ms(lambda: ForwardSecureHMACStream.commit(events, seed_key))
    (_, verify_ms) = _time_ms(lambda: ForwardSecureHMACStream.verify(events, commitment, seed_key))
    (_, partial_ms) = _time_ms(lambda: ForwardSecureHMACStream.verify_prefix(events, commitment, seed_key, pivot))
    detection = _attack_detection_rate(
        events,
        args.seed + repetition,
        lambda attacked: ForwardSecureHMACStream.verify(attacked, commitment, seed_key),
    )
    rows.append(
        {
            "system": "forward_secure_hmac_stream_model",
            "granularity": "per_event_local_tag",
            "build_ms": build_ms,
            "append_us_per_event": build_ms * 1000.0 / len(events),
            "full_verify_ms": verify_ms,
            "partial_check_ms": partial_ms,
            "tamper_detection_rate": detection,
            "proof_or_receipt_bytes": 40,
            "commitment_bytes": 40,
            "scope_note": "user-space forward-secure HMAC model; not Nitro",
        }
    )

    batch_commitment, build_ms = _time_ms(
        lambda: BatchReducedHMACStream.commit(events, seed_key, args.batch_size)
    )
    (_, verify_ms) = _time_ms(lambda: BatchReducedHMACStream.verify(events, batch_commitment, seed_key))
    (_, partial_ms) = _time_ms(
        lambda: BatchReducedHMACStream.verify_prefix(events, seed_key, pivot, args.batch_size)
    )
    detection = _attack_detection_rate(
        events,
        args.seed + repetition,
        lambda attacked: BatchReducedHMACStream.verify(attacked, batch_commitment, seed_key),
    )
    rows.append(
        {
            "system": "batch_reduced_fs_hmac_model",
            "granularity": f"batch_{args.batch_size}_local_tag",
            "build_ms": build_ms,
            "append_us_per_event": build_ms * 1000.0 / len(events),
            "full_verify_ms": verify_ms,
            "partial_check_ms": partial_ms,
            "tamper_detection_rate": detection,
            "proof_or_receipt_bytes": 40,
            "commitment_bytes": 40,
            "scope_note": "batch-reduced local model inspired by eBPF/Nitro-R placement; not Nitro-R",
        }
    )

    ledger_commitment, build_ms = _time_ms(
        lambda: MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
    )
    (_, verify_ms) = _time_ms(lambda: MerkleSignedLog.verify(events, ledger_commitment, registry))
    proof, proof_gen_ms = _time_ms(lambda: MerkleSignedLog.gen_inclusion_proof(events, pivot))
    (_, proof_verify_ms) = _time_ms(
        lambda: MerkleSignedLog.verify_inclusion_proof(events[pivot], pivot, proof, ledger_commitment.root_hash)
    )
    detection = _attack_detection_rate(
        events,
        args.seed + repetition,
        lambda attacked: MerkleSignedLog.verify(attacked, ledger_commitment, registry),
    )
    rows.append(
        {
            "system": "ledgershield_merkle_signed",
            "granularity": "transferable_inclusion_proof",
            "build_ms": build_ms,
            "append_us_per_event": build_ms * 1000.0 / len(events),
            "full_verify_ms": verify_ms,
            "partial_check_ms": proof_gen_ms + proof_verify_ms,
            "tamper_detection_rate": detection,
            "proof_or_receipt_bytes": len(json.dumps(proof).encode("utf-8")),
            "commitment_bytes": len(json.dumps(ledger_commitment.to_dict(), sort_keys=True).encode("utf-8")),
            "scope_note": "LedgerShield artifact path with Ed25519 STH and CT-style proof",
        }
    )

    return rows


def _aggregate(rows: List[Dict]) -> Dict:
    aggregate: Dict[str, Dict] = {}
    for system in sorted({row["system"] for row in rows}):
        subset = [row for row in rows if row["system"] == system]
        first = subset[0]
        metrics = {
            name: _summary([float(row[name]) for row in subset])
            for name in [
                "build_ms",
                "append_us_per_event",
                "full_verify_ms",
                "partial_check_ms",
                "tamper_detection_rate",
            ]
        }
        aggregate[system] = {
            "granularity": first["granularity"],
            "proof_or_receipt_bytes": first["proof_or_receipt_bytes"],
            "commitment_bytes": first["commitment_bytes"],
            "scope_note": first["scope_note"],
            "metrics": metrics,
        }
    return aggregate


def _write_csv(path: str, rows: List[Dict]) -> None:
    fieldnames = [
        "system",
        "granularity",
        "build_ms",
        "append_us_per_event",
        "full_verify_ms",
        "partial_check_ms",
        "tamper_detection_rate",
        "proof_or_receipt_bytes",
        "commitment_bytes",
        "scope_note",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare LedgerShield with forward-secure/eBPF-style secure-logging models."
    )
    parser.add_argument("--events-jsonl", default="data/berka/events.jsonl")
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="calibrated")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--run-id", default="secure_logger_comparison")
    args = parser.parse_args()

    if args.num_events <= 0:
        raise ValueError("--num-events must be > 0")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")
    if args.repetitions <= 0:
        raise ValueError("--repetitions must be > 0")

    events = _load_events(args)
    if len(events) < args.num_events:
        raise ValueError(f"requested {args.num_events} events but loaded {len(events)}")

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    rows: List[Dict] = []
    for repetition in range(1, args.repetitions + 1):
        rows.extend(run_once(args, events, repetition))

    aggregate = _aggregate(rows)
    payload = {
        "input": {
            "events_jsonl": args.events_jsonl if os.path.exists(args.events_jsonl) else "",
            "num_events": len(events),
            "workload": "berka" if os.path.exists(args.events_jsonl) else args.workload,
            "seed": args.seed,
            "repetitions": args.repetitions,
            "batch_size": args.batch_size,
        },
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "scope": {
            "nitro_available": False,
            "claim": (
                "This is a reproducible local comparison against forward-secure "
                "and batch-reduced cryptographic secure-logging models. It is "
                "not a live Nitro/eBPF kernel benchmark."
            ),
        },
        "aggregate": aggregate,
        "rows": rows,
    }
    csv_path = os.path.join(results_dir, "secure_logger_comparison.csv")
    json_path = os.path.join(results_dir, "secure_logger_comparison.json")
    _write_csv(csv_path, rows)
    payload["checksums"] = {
        "secure_logger_comparison_csv_sha256": sha256_hex(open(csv_path, "r", encoding="utf-8").read())
    }
    write_json(json_path, payload)
    print(json.dumps({"secure_logger_comparison_json": json_path}, indent=2))


if __name__ == "__main__":
    main()
