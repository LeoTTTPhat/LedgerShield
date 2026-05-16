import argparse
import json
import math
import os
import subprocess
import sys
from typing import Dict, List

from common import write_json


def mean(xs: List[float]) -> float:
    return sum(xs) / max(1, len(xs))


def stdev(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def ci95(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    t95_by_df = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571}
    return t95_by_df.get(len(xs) - 1, 1.96) * stdev(xs) / math.sqrt(len(xs))


def load(path: str) -> Dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events-jsonl", default=os.path.join("data", "berka", "events.jsonl"))
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--run-prefix", default="immudb_live_berka_rep")
    parser.add_argument("--aggregate-id", default="immudb_live_berka_repeated")
    args = parser.parse_args()

    rows = []
    for rep in range(1, args.repetitions + 1):
        run_id = f"{args.run_prefix}{rep}"
        cmd = [
            sys.executable,
            "src/run_immudb_live_baseline.py",
            "--events-jsonl",
            args.events_jsonl,
            "--num-events",
            str(args.num_events),
            "--start-server",
            "--run-id",
            run_id,
            "--data-dir",
            os.path.join("results", f"{run_id}_data"),
        ]
        subprocess.run(cmd, check=True)
        rows.append(load(os.path.join("results", run_id, "immudb_live_baseline.json")))

    metrics = ["set_latency_ms_mean", "set_latency_ms_min", "set_latency_ms_max", "verified_get_latency_ms_mean"]
    aggregate = {
        "events_jsonl": args.events_jsonl,
        "num_events": args.num_events,
        "repetitions": args.repetitions,
        "rows": rows,
        "aggregate": {},
    }
    for metric in metrics:
        values = [float(row[metric]) for row in rows]
        aggregate["aggregate"][metric] = {
            "mean": mean(values),
            "std": stdev(values),
            "ci95": ci95(values),
        }

    out_dir = os.path.join("results", args.aggregate_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "immudb_live_repeated.json")
    write_json(out_path, aggregate)
    print(json.dumps({"aggregate_json": out_path}, indent=2))


if __name__ == "__main__":
    main()
