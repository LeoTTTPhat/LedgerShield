# LedgerShield Code Artifacts

This folder contains the code and reproducibility artifacts for the LedgerShield
paper package. It intentionally excludes the manuscript, TeX sources, generated
PDFs, LaTeX auxiliary files, virtual environments, caches, private keys, and
generated service databases.

## Contents

- `src/`: LedgerShield implementation, baselines, workload importers, benchmark
  harnesses, anchoring demos, malicious-writer evaluation, and service-baseline
  drivers, including the writer-side batching-cost harness.
- `tests/`: unit and robustness tests for the core verifier, consistency proofs,
  and malicious-writer extension.
- `configs/`: non-secret configuration and key registry metadata. Private keys
  are not included.
- `data/`: public/processed workload inputs used by the artifact, excluding
  generated SQLite database files.
- `results/`: reproducible JSON/CSV/JSONL result artifacts and manifests,
  excluding private PEM files and live immudb database directories.
  `results/writer_costs/` contains the append/checkpoint/proof/memory
  experiment for per-event, per-batch, and time-window checkpoint policies.
- `README.md`, `ARTIFACT.md`, `Makefile`, `Dockerfile`, `requirements.txt`:
  reviewer-facing setup and reproduction files.

## Quick Checks

From this directory:

```bash
python3 -m pip install -r requirements.txt
python3 -m pytest tests
make smoke
```

Some live baseline commands require external services or binaries such as immudb,
Trillian, MariaDB, or OpenTimestamps tooling; the corresponding result JSON files
are included where available.
