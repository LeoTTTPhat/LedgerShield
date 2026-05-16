import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from typing import Dict, List

from common import generate_events, write_json
from merkle_signed_log import KeyRegistry, MerkleSignedLog


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
    parser.add_argument("--run-id", default="external_anchoring")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--rfc3161-cmd", default="")
    parser.add_argument("--opentimestamps-cmd", default="")
    args = parser.parse_args()

    results_dir = os.path.join("results", args.run_id)
    key_dir = os.path.join("configs", "keys")
    registry_path = os.path.join("configs", "key_registry.json")
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)

    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    events = generate_events(args.num_events, args.seed, args.workload)
    commitment = MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
    commitment_json = json.dumps(commitment.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    commitment_path = os.path.join(results_dir, "commitment.json")
    digest_path = os.path.join(results_dir, "commitment.sha256")
    with open(commitment_path, "wb") as f:
        f.write(commitment_json)
    digest_hex = hashlib.sha256(commitment_json).hexdigest()
    with open(digest_path, "w", encoding="utf-8") as f:
        f.write(digest_hex + "\n")

    results = {
        "workload": args.workload,
        "num_events": args.num_events,
        "seed": args.seed,
        "commitment_path": commitment_path,
        "commitment_sha256": digest_hex,
        "external_anchors": {},
    }

    if args.rfc3161_cmd:
        results["external_anchors"]["rfc3161"] = _run_checked(
            shlex.split(args.rfc3161_cmd.format(commitment=commitment_path, digest=digest_path)),
            args.timeout,
        )
    else:
        results["external_anchors"]["rfc3161"] = {
            "status": "skipped",
            "reason": "pass --rfc3161-cmd with a local TSA command; placeholders: {commitment}, {digest}",
            "openssl_present": shutil.which("openssl") is not None,
        }

    if args.opentimestamps_cmd:
        results["external_anchors"]["opentimestamps"] = _run_checked(
            shlex.split(args.opentimestamps_cmd.format(commitment=commitment_path, digest=digest_path)),
            args.timeout,
        )
    else:
        results["external_anchors"]["opentimestamps"] = {
            "status": "skipped",
            "reason": "pass --opentimestamps-cmd with a local ots command; placeholders: {commitment}, {digest}",
            "ots_present": shutil.which("ots") is not None or shutil.which("ots-cli") is not None,
        }

    out_path = os.path.join(results_dir, "external_anchoring.json")
    write_json(out_path, results)
    print(json.dumps({"external_anchoring_json": out_path}, indent=2))


if __name__ == "__main__":
    main()
