# Commitment-Signed Financial Audit Logs

CPU-first benchmark for tamper-evident financial event logging.

## What this includes

- Baseline A: append-only CSV (`baseline_csv.py`)
- Baseline B: hash-chain log (`baseline_hashchain.py`)
- Baseline C: SQLite audit table with per-row hash-chain receipts (`baseline_sqlite.py`)
- Proposed: Merkle commitment + Ed25519 signatures with trusted key registry (`merkle_signed_log.py`)
- Optional witness anchoring (`witness_anchor.py`)
- Malicious-writer extension (`malicious_writer.py`): policy-signer monotonicity, quorum witness certificates, and completeness-source auditing
- Attack suite: insert/delete/modify/replay/truncate (`attacks.py`)
- Benchmark runner with reproducible seeds (`run_benchmark.py`)

## Quick start

```bash
cd LedgerShield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 src/run_benchmark.py --num-events 1000 --seed 42 --run-id exp01
python3 -m unittest discover -s tests -p "test_*.py"
python3 src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix ms01
python3 src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix calibrated01 --workload calibrated
python3 src/run_scaling.py --sizes 1000,10000,100000 --seed 42 --repetitions 5 --run-id scaling01
python3 src/run_writer_costs.py --sizes 1000,10000,100000 --seed 42 --repetitions 3 --batch-sizes 1,256,10000 --time-windows 60 --proof-samples 4 --workload calibrated --run-id writer_costs
python3 src/run_ablation.py --num-events 1000 --seed 42 --run-id ablation01
python3 src/run_external_baselines.py --num-events 1000 --seed 42 --workload calibrated --run-id external01
python3 src/run_external_anchoring.py --num-events 1000 --seed 42 --workload calibrated --run-id anchor01
PATH="$PWD/.venv_ots/bin:$PATH" python3 src/run_ots_anchoring.py --num-events 1000 --seeds 42,123,999 --workload calibrated --run-id ots_anchoring --timeout 20
python3 src/run_multiprocess_witness_demo.py --events-jsonl data/berka/events.jsonl --num-events 1000 --run-id multiprocess_witness_demo
python3 src/fetch_public_bitcoin_workload.py --num-events 1000 --out-dir data/public_bitcoin
python3 src/run_benchmark.py --num-events 1000 --events-jsonl data/public_bitcoin/events.jsonl --workload public_bitcoin --run-id public_bitcoin
python3 src/fetch_berka_workload.py --num-events 1000 --out-dir data/berka
python3 src/run_benchmark.py --num-events 1000 --events-jsonl data/berka/events.jsonl --workload berka --run-id berka
python3 src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix berka_ms --workload berka --events-jsonl data/berka/events.jsonl
python3 src/run_immudb_live_baseline.py --events-jsonl data/berka/events.jsonl --num-events 1000 --start-server --run-id immudb_live_berka_1000
python3 src/run_immudb_repeated.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 3 --run-prefix immudb_live_berka_rep --aggregate-id immudb_live_berka_repeated
python3 src/run_malicious_writer_eval.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 5 --run-id malicious_writer_eval
python3 src/run_secure_logger_comparison.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 5 --batch-size 64 --run-id secure_logger_comparison
```

Or use the included Makefile:

```bash
make test
make benchmark
make calibrated
make scaling
make writer-costs
make ablation
make external
make anchor
make ots-anchor
make multiprocess-witness
make stress
make public-bitcoin
make berka
make berka-repeat
make immudb-live
make immudb-repeat
make malicious-writer
make secure-logger-comparison
```

The real Trillian service-stack comparison requires Go, MariaDB, and the
official Trillian binaries (`trillian_log_server`, `trillian_log_signer`,
and `createtree`) from the Google Trillian repository. The archived run
used a single local Trillian server, signer and MariaDB backend over
localhost gRPC.

Outputs:

- `results/<run-id>/benchmark_results.csv`
- `results/<run-id>/benchmark_summary.json`
- `results/<run-id>/repro_manifest.json`
- `results/<run-prefix>_aggregate.csv` and `results/<run-prefix>_aggregate.json` (multi-seed stats)
- `results/<run-prefix>_aggregate.json` for calibrated public-style financial workloads
- `results/<run-id>/scaling_results.csv` and `results/<run-id>/scaling_results.json`
- `results/<run-id>/writer_costs_raw.csv`, `writer_costs_aggregate.csv`, and `writer_costs.json`
- `results/<run-id>/ablation_results.csv` and `results/<run-id>/ablation_results.json`
- `results/<run-id>/external_baselines.json` with skipped/completed Trillian and immudb harness status
- `results/<run-id>/external_anchoring.json` with skipped/completed RFC 3161/OpenTimestamps status
- `results/ots_anchoring/ots_anchoring.json` with live OpenTimestamps public-calendar pending receipts when the OTS client is installed
- `results/multiprocess_witness_demo/multiprocess_witness_demo.json` with five local witness processes, distinct keys/state, quorum verification, and conflict rejection
- `data/public_bitcoin/events.jsonl` and `data/public_bitcoin/manifest.json` for the real public Bitcoin trace
- `data/berka/events.jsonl` and `data/berka/manifest.json` for the real anonymized Czech-bank trace
- `results/berka/benchmark_summary.json` for LedgerShield and local baselines on the Berka trace
- `results/berka_ms_aggregate.json` for mean/std/CI95 Berka repeated attack-benchmark statistics
- `results/immudb_live_berka_1000/immudb_live_baseline.json` for the live immudb client/server baseline
- `results/immudb_live_berka_repeated/immudb_live_repeated.json` for mean/std/CI95 repeated live immudb smoke-baseline statistics
- `results/trillian_live_berka_1000/trillian_live_baseline.json` for the real local Trillian server/signer/MariaDB service-stack baseline
- `results/production_service_comparison/production_service_comparison.json` for the combined LedgerShield/Trillian/immudb service-stack comparison
- `results/malicious_writer_eval/malicious_writer_eval.json` for repeated policy-signer monotonicity, 3-of-5 witness quorum, and completeness-source auditing on Berka
- `results/secure_logger_comparison/secure_logger_comparison.json` for the forward-secure/eBPF-style cryptographic model comparison on Berka
- `configs/key_registry.json` and `configs/keys/*.pem`

## Metrics

- `tamper_detection_rate`
- `avg_verification_latency_ms`
- `avg_proof_size_bytes`
- `avg_commitment_size_bytes`
- `avg_attacked_log_size_bytes`
- `avg_artifact_overhead_ratio`

Multi-seed aggregate adds:

- `*_mean`
- `*_std`
- `*_ci95`

## Notes

- Uses Ed25519 via `cryptography`.
- Synthetic event generation is included; no paid API, no GPU.
- Deterministic generation: same seed => same dataset bytes.

## Claim Scope (for paper/report wording)

Supported claims in current implementation:

- Tamper-evident logging with Merkle commitments and Ed25519 signatures.
- Reproducible benchmark artifacts (single-run + multi-seed summary with mean/std/CI95).
- Scaling artifacts for commit, inclusion, consistency, and witness-anchor operations.
- Writer-side cost artifacts for streaming append, checkpoint signing, sampled proof generation, memory footprint, and per-event/per-batch/time-based checkpoint policies.
- Ablation artifacts for tuple binding and witness rollback detection.
- Calibrated public-style financial workload with account skew, heavy-tailed amounts, and bursty timestamps.
- Real public Bitcoin transaction trace imported from Blockstream Esplora.
- Real anonymized Berka/PKDD'99 Czech-bank transaction trace.
- Live local immudb baseline using `immudb` and `immuclient safeset/safeget`.
- Real local Trillian service-stack baseline using official Trillian binaries and MariaDB.
- Forward-secure and batch-reduced secure-logging model comparison inspired by host/eBPF loggers such as Nitro, explicitly not a live Nitro kernel benchmark.
- Optional external baseline harness hooks for local Trillian and immudb deployments.
- Optional external anchoring hooks for local RFC 3161 TSA or OpenTimestamps commands.
- Live OpenTimestamps public-calendar pending-receipt run over three calibrated commitments, when the OTS client is installed.
- Multi-process local witness-quorum demo with distinct witness keys and state files.
- Artifact-level consistency proof verification (including optional proof-signature binding).
- Local witness anchoring that detects storage rollback relative to the witness's latest record.
- Malicious-writer extension artifact with stateful policy-signer monotonicity, local quorum witness certificates, and completeness-source auditing against expected source identifiers.

Not supported (do not claim without additional mechanisms):

- Trustless global ordering across independent operators.
- Final external timestamp notarization guarantees before OTS Bitcoin confirmation or a verified RFC 3161 token.
- Full anti-equivocation guarantees without external witness/transparency-log infrastructure.
- Completeness guarantees without an independent source-of-truth sequence.
