import argparse
import json
import os
import shlex
import shutil
import subprocess
import time
from typing import Dict, List

from common import generate_events, write_json


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_checked(cmd: List[str], timeout: int) -> Dict:
    t0 = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "status": "completed",
            "elapsed_ms": (time.perf_counter() - t0) * 1000.0,
            "stdout": completed.stdout[-2000:],
            "stderr": completed.stderr[-2000:],
        }
    except Exception as exc:
        return {
            "status": "failed",
            "elapsed_ms": (time.perf_counter() - t0) * 1000.0,
            "error": str(exc),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--workload", choices=["synthetic", "calibrated"], default="calibrated")
    parser.add_argument("--run-id", default="external_baselines")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--immuclient-cmd", default="")
    parser.add_argument("--trillian-cmd", default="")
    args = parser.parse_args()

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    # Materialize the workload so external harnesses can consume the exact same bytes.
    events = generate_events(args.num_events, args.seed, args.workload)
    workload_path = os.path.join(results_dir, "workload.jsonl")
    with open(workload_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(event.canonical_json() + "\n")

    results = {
        "workload_path": workload_path,
        "workload": args.workload,
        "num_events": args.num_events,
        "seed": args.seed,
        "external_baselines": {},
    }

    if args.immuclient_cmd:
        results["external_baselines"]["immudb"] = _run_checked(
            shlex.split(args.immuclient_cmd.format(workload=workload_path)),
            args.timeout,
        )
    else:
        results["external_baselines"]["immudb"] = {
            "status": "skipped",
            "reason": "pass --immuclient-cmd with a local immudb harness command",
            "tool_present": _tool_available("immuclient"),
        }

    if args.trillian_cmd:
        results["external_baselines"]["trillian"] = _run_checked(
            shlex.split(args.trillian_cmd.format(workload=workload_path)),
            args.timeout,
        )
    else:
        results["external_baselines"]["trillian"] = {
            "status": "skipped",
            "reason": "pass --trillian-cmd with a local Trillian harness command",
            "tool_present": _tool_available("trillian_log_server"),
        }

    out_path = os.path.join(results_dir, "external_baselines.json")
    write_json(out_path, results)
    print(json.dumps({"external_baselines_json": out_path}, indent=2))


if __name__ == "__main__":
    main()
