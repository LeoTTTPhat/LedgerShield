import argparse
import base64
import json
import os
import shutil
import subprocess
import time
from typing import Dict, List

from common import read_events_jsonl, write_json


def _run(
    cmd: List[str],
    timeout: int = 30,
    check: bool = False,
    cwd: str | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
        cwd=cwd,
    )


def _immuclient_args(args: argparse.Namespace) -> List[str]:
    return [
        args.immuclient,
        "--immudb-address",
        args.address,
        "--immudb-port",
        str(args.port),
        "--username",
        args.user,
        "--password",
        args.password,
        "--database",
        args.database,
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events-jsonl", default=os.path.join("data", "public_bitcoin", "events.jsonl"))
    parser.add_argument("--num-events", type=int, default=100)
    parser.add_argument("--run-id", default="immudb_live_public_bitcoin")
    parser.add_argument("--immudb", default=shutil.which("immudb") or "immudb")
    parser.add_argument("--immuclient", default=shutil.which("immuclient") or "immuclient")
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3322)
    parser.add_argument("--user", default="immudb")
    parser.add_argument("--password", default="immudb")
    parser.add_argument("--database", default="defaultdb")
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--data-dir", default=os.path.join("results", "immudb_data"))
    parser.add_argument("--client-dir", default=None)
    args = parser.parse_args()

    args.immuclient = shutil.which(args.immuclient) or args.immuclient
    args.immudb = shutil.which(args.immudb) or args.immudb

    if not os.path.exists(args.immuclient):
        raise RuntimeError("immuclient not found; install immudb or pass --immuclient")
    if args.start_server and not os.path.exists(args.immudb):
        raise RuntimeError("immudb not found; install immudb or pass --immudb")

    results_dir = os.path.join("results", args.run_id)
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(args.data_dir, exist_ok=True)
    client_dir = args.client_dir or os.path.join(results_dir, "immuclient_state")
    os.makedirs(client_dir, exist_ok=True)
    events = read_events_jsonl(args.events_jsonl, args.num_events)
    if len(events) < args.num_events:
        raise ValueError(f"requested {args.num_events} events but loaded {len(events)}")

    server = None
    if args.start_server:
        server = subprocess.Popen(
            [
                args.immudb,
                "--dir",
                args.data_dir,
                "--address",
                args.address,
                "--port",
                str(args.port),
                "--auth",
                "--admin-password",
                args.password,
                "--force-admin-password",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(2.0)

    try:
        base = _immuclient_args(args)
        health = _run(base + ["health"], timeout=15, cwd=client_dir)
        if health.returncode != 0:
            raise RuntimeError(f"immuclient health failed: {health.stderr or health.stdout}")

        set_latencies = []
        for event in events:
            key = base64.b64encode(f"ls:{args.run_id}:{event.event_id:08d}".encode("utf-8")).decode("ascii")
            value = base64.b64encode(event.canonical_json().encode("utf-8")).decode("ascii")
            t0 = time.perf_counter()
            completed = _run(base + ["safeset", key, value], timeout=30, cwd=client_dir)
            elapsed = (time.perf_counter() - t0) * 1000.0
            if completed.returncode != 0:
                raise RuntimeError(f"immuclient safeset failed: {completed.stderr or completed.stdout}")
            set_latencies.append(elapsed)

        verify_samples = []
        for event in (events[0], events[len(events) // 2], events[-1]):
            key = base64.b64encode(f"ls:{args.run_id}:{event.event_id:08d}".encode("utf-8")).decode("ascii")
            t0 = time.perf_counter()
            completed = _run(base + ["safeget", key], timeout=30, cwd=client_dir)
            elapsed = (time.perf_counter() - t0) * 1000.0
            if completed.returncode != 0:
                raise RuntimeError(f"immuclient safeget failed: {completed.stderr or completed.stdout}")
            verify_samples.append(elapsed)

        result: Dict = {
            "status": "completed",
            "system": "immudb",
            "events_jsonl": args.events_jsonl,
            "num_events": len(events),
            "started_server": bool(args.start_server),
            "address": args.address,
            "port": args.port,
            "client_dir": client_dir,
            "set_latency_ms_mean": sum(set_latencies) / len(set_latencies),
            "set_latency_ms_min": min(set_latencies),
            "set_latency_ms_max": max(set_latencies),
            "verified_get_latency_ms_mean": sum(verify_samples) / len(verify_samples),
            "verified_get_latency_ms_samples": verify_samples,
        }
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

    out_path = os.path.join(results_dir, "immudb_live_baseline.json")
    write_json(out_path, result)
    print(json.dumps({"immudb_live_baseline_json": out_path}, indent=2))


if __name__ == "__main__":
    main()
