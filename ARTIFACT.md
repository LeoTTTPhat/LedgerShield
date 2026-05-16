# LedgerShield Artifact Guide

This artifact accompanies the LedgerShield manuscript. It is intended to
reproduce the unit tests, attack benchmark, scaling benchmark and ablation
study without external services.

## Environment

- Python 3.11 or newer
- `cryptography==45.0.4`
- SQLite from the Python standard library
- Optional for `make ots-anchor`: `opentimestamps-client` installed in
  `.venv_ots` or another environment that puts the `ots` binary on `PATH`

## One-command checks

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make PYTHON=.venv/bin/python test
make PYTHON=.venv/bin/python benchmark
make PYTHON=.venv/bin/python calibrated
make PYTHON=.venv/bin/python scaling
make PYTHON=.venv/bin/python writer-costs
make PYTHON=.venv/bin/python stress
make PYTHON=.venv/bin/python ablation
make PYTHON=.venv/bin/python external
make PYTHON=.venv/bin/python anchor
make PYTHON=.venv/bin/python ots-anchor
make PYTHON=.venv/bin/python multiprocess-witness
make PYTHON=.venv/bin/python public-bitcoin
make PYTHON=.venv/bin/python berka
make PYTHON=.venv/bin/python berka-repeat
make PYTHON=.venv/bin/python malicious-writer
make PYTHON=.venv/bin/python secure-logger-comparison
```

The live immudb baseline requires Homebrew immudb binaries:

```bash
brew install immudb
make PYTHON=.venv/bin/python immudb-live
make PYTHON=.venv/bin/python immudb-repeat
```

The real Trillian service-stack comparison additionally requires Go,
MariaDB, and official Trillian binaries built from the Google Trillian
repository. The archived run used a single local Trillian log server,
log signer and MariaDB backend over localhost gRPC.

## Expected outputs

- `results/ms_aggregate.json`: attack benchmark across seeds 42, 123 and 999.
- `results/calibrated_ms_aggregate.json`: same benchmark on the calibrated public-style workload.
- `results/scaling/scaling_results.json`: 1K/10K/100K scaling rows.
- `results/writer_costs/writer_costs.json`: writer-side append, checkpoint-signing, sampled inclusion-proof generation, and memory rows under per-event, per-256-event, per-10000-event and 60-second checkpoint policies.
- `results/stress_1m/scaling_results.json`: calibrated 1K/10K/100K/1M stress rows.
- `results/ablation/ablation_results.json`: tuple-binding and witness ablation rows.
- `results/external_baselines/external_baselines.json`: status for optional Trillian/immudb harnesses.
- `results/external_anchoring/external_anchoring.json`: status for optional RFC 3161/OpenTimestamps anchoring.
- `results/ots_anchoring/ots_anchoring.json`: live OpenTimestamps public-calendar pending receipts when the `ots` client is installed.
- `results/multiprocess_witness_demo/multiprocess_witness_demo.json`: five-process, independently keyed local witness-quorum demo.
- `data/public_bitcoin/events.jsonl`: real public Bitcoin transactions converted to LedgerShield events.
- `data/public_bitcoin/manifest.json`: source block hash, height, timestamp and schema mapping.
- `data/berka/events.jsonl`: real anonymized PKDD'99/Berka Czech-bank transactions converted to LedgerShield events.
- `data/berka/manifest.json`: source URL and schema mapping for the Berka trace.
- `results/public_bitcoin/benchmark_summary.json`: LedgerShield and local baselines on the public trace.
- `results/berka/benchmark_summary.json`: LedgerShield and local baselines on the real institutional trace.
- `results/berka_ms_aggregate.json`: mean/std/CI95 Berka repeated attack-benchmark statistics.
- `results/immudb_live_berka_1000/immudb_live_baseline.json`: live immudb client/server smoke baseline on the Berka trace.
- `results/immudb_live_berka_repeated/immudb_live_repeated.json`: mean/std/CI95 repeated live immudb smoke-baseline statistics.
- `results/trillian_live_berka_1000/trillian_live_baseline.json`: real local Trillian server/signer/MariaDB service-stack baseline.
- `results/production_service_comparison/production_service_comparison.json`: combined LedgerShield/Trillian/immudb service-stack comparison.
- `results/malicious_writer_eval/malicious_writer_eval.json`: repeated malicious-writer extension evaluation on Berka with mean/std/CI95.
- `results/secure_logger_comparison/secure_logger_comparison.json`: forward-secure/eBPF-style cryptographic model comparison on Berka with mean/std/CI95.
- `configs/key_registry.json` and `configs/keys/*.pem`: generated local keys.

Generated private keys and benchmark outputs are ignored by git. Delete
`configs/` and `results/` to rerun from a clean state.

## Scope

The calibrated workload is not private bank data. It is a deterministic
public-style generator with account skew, bursty timestamps, and
heavy-tailed transaction amounts, designed to stress event sizes and
ordering while remaining redistributable.

The public Bitcoin workload is real public blockchain data fetched from
Blockstream Esplora and converted into the same event schema. It improves
external validity but is still not a private banking audit trace.

The Berka workload is a real anonymized institutional banking trace from
the PKDD'99 Czech financial dataset, converted from the transaction table
in the Teradata TSV mirror. It is historical and anonymized, but closer to
the target audit-log setting than a synthetic generator or public
blockchain trace.

The immudb live baseline starts a local authenticated immudb server and
uses `immuclient safeset` / `safeget` over loopback on the Berka trace. It
is a real client/server smoke baseline, not a tuned production immudb
deployment. The repeated target runs the same smoke baseline three times
and aggregates mean, standard deviation and 95% confidence intervals.

The Trillian live baseline starts official Trillian log-server and
log-signer binaries against MariaDB, creates a fresh LOG tree, queues the
Berka workload through gRPC, waits for sequencing, and requests a signed
root plus inclusion proof. It exercises production Trillian code paths but
is still a single-node localhost run, not a tuned clustered deployment.

The malicious-writer extension target is repeated local artifact evidence for the
paper's stronger model. It evaluates a stateful policy signer that rejects
duplicate checkpoint sequences and decreasing tree sizes, a 3-of-5 local
witness certificate quorum that rejects same-slot conflicts, and a
completeness-source audit that compares logged Berka source identifiers
against an expected sequence. The default target runs five repetitions and
reports mean, standard deviation and 95% confidence intervals. This is not
an HSM, TSA, or public-witness deployment, but it makes the proposed
controls executable and testable.

The multi-process witness demo starts five independent OS processes on
one host. Each process owns a separate witness key and state file, signs
the same checkpoint, and emits a certificate that the parent verifies
under a 3-of-5 policy. A follow-up process reuses witness `w1`'s state and
attempts to sign a conflicting same-slot successor; the expected result is
rejection. This is stronger than an in-process quorum unit test, but it is
still not a multi-organization witness deployment.

The secure-logger comparison target evaluates two local cryptographic
models inspired by forward-secure and eBPF-assisted host loggers: a
per-event HMAC stream with key evolution, and a batch-reduced HMAC stream
with 64-event batches. These runs are useful for comparing local
cryptographic costs and evidence granularity against LedgerShield on the
same Berka trace and attack suite. They are explicitly not a live Nitro or
Nitro-R kernel/eBPF benchmark.

The artifact includes a local witness-anchor prototype. It demonstrates
rollback detection relative to an independent append-only witness file, but
it is not a public timestamping service, a CT log, or a blockchain. External
anchoring integrations are deployment options discussed in the paper.

The external baseline runner materializes the exact workload as JSONL and
records whether local Trillian or immudb harness commands were provided. It
does not fabricate numbers when those services are absent.

The external anchoring runner writes the exact commitment bytes and their
SHA-256 digest, then records whether RFC 3161 or OpenTimestamps commands
were supplied. It likewise reports skipped status rather than synthetic
anchor latency when no external service is configured. The separate
OpenTimestamps harness can use a real public calendar when the `ots`
client is available. The archived run stamped three calibrated
commitments through `a.pool.opentimestamps.org`, produced three pending
`.ots` receipts, and recorded `ots verify` as pending Bitcoin
confirmation. A later `ots upgrade` attempt still reported pending
confirmation. That is live public-calendar evidence, not final block
confirmation or RFC 3161 TSA evidence.
