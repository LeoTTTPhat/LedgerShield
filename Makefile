.PHONY: test benchmark calibrated scaling writer-costs ablation external anchor ots-anchor multiprocess-witness stress public-bitcoin berka berka-repeat immudb-live immudb-repeat malicious-writer secure-logger-comparison smoke scaling-billion

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py"

benchmark:
	$(PYTHON) src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix ms

calibrated:
	$(PYTHON) src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix calibrated_ms --workload calibrated

scaling:
	$(PYTHON) src/run_scaling.py --sizes 1000,10000,100000 --seed 42 --repetitions 5 --run-id scaling

writer-costs:
	$(PYTHON) src/run_writer_costs.py --sizes 1000,10000,100000 --seed 42 --repetitions 3 --batch-sizes 1,256,10000 --time-windows 60 --proof-samples 4 --workload calibrated --run-id writer_costs

ablation:
	$(PYTHON) src/run_ablation.py --num-events 1000 --seed 42 --run-id ablation

external:
	$(PYTHON) src/run_external_baselines.py --num-events 1000 --seed 42 --workload calibrated --run-id external_baselines

anchor:
	$(PYTHON) src/run_external_anchoring.py --num-events 1000 --seed 42 --workload calibrated --run-id external_anchoring

ots-anchor:
	PATH="$$(pwd)/.venv_ots/bin:$$PATH" $(PYTHON) src/run_ots_anchoring.py --num-events 1000 --seeds 42,123,999 --workload calibrated --run-id ots_anchoring --timeout 20

multiprocess-witness:
	$(PYTHON) src/run_multiprocess_witness_demo.py --events-jsonl data/berka/events.jsonl --num-events 1000 --run-id multiprocess_witness_demo

stress:
	$(PYTHON) src/run_scaling.py --sizes 1000,10000,100000,1000000 --seed 42 --repetitions 3 --run-id stress_1m --workload calibrated

public-bitcoin:
	$(PYTHON) src/fetch_public_bitcoin_workload.py --num-events 1000 --out-dir data/public_bitcoin
	$(PYTHON) src/run_benchmark.py --num-events 1000 --events-jsonl data/public_bitcoin/events.jsonl --workload public_bitcoin --run-id public_bitcoin

berka:
	$(PYTHON) src/fetch_berka_workload.py --num-events 1000 --out-dir data/berka
	$(PYTHON) src/run_benchmark.py --num-events 1000 --events-jsonl data/berka/events.jsonl --workload berka --run-id berka

berka-repeat:
	$(PYTHON) src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix berka_ms --workload berka --events-jsonl data/berka/events.jsonl

immudb-live:
	$(PYTHON) src/run_immudb_live_baseline.py --events-jsonl data/berka/events.jsonl --num-events 1000 --start-server --run-id immudb_live_berka_1000

immudb-repeat:
	$(PYTHON) src/run_immudb_repeated.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 3 --run-prefix immudb_live_berka_rep --aggregate-id immudb_live_berka_repeated

malicious-writer:
	$(PYTHON) src/run_malicious_writer_eval.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 5 --run-id malicious_writer_eval

secure-logger-comparison:
	$(PYTHON) src/run_secure_logger_comparison.py --events-jsonl data/berka/events.jsonl --num-events 1000 --repetitions 5 --batch-size 64 --run-id secure_logger_comparison

smoke:
	$(PYTHON) src/run_benchmark.py --num-events 100 --seed 42 --run-id smoke

scaling-billion:
	$(PYTHON) src/run_scaling_billion.py --sizes 1000,10000,100000,1000000 --projected 1000000000 --seed 42 --workload calibrated --run-id scaling_billion
