"""aggregate non-production architectural model outputs.

This helper is not for live Trillian or immudb benchmark reporting.
"""
import json, os, math, statistics, argparse

def ci95(vals):
    if len(vals) < 2:
        return 0.0
    return 1.96 * statistics.stdev(vals) / math.sqrt(len(vals))

def load_rows(run_ids, base="results"):
    all_rows = []
    for rid in run_ids:
        path = os.path.join(base, rid, "head_to_head.json")
        with open(path) as f:
            d = json.load(f)
        all_rows.extend(d["rows"])
    return all_rows

def aggregate(rows):
    """Group by size, compute mean/std/ci95 for every numeric field."""
    from collections import defaultdict
    groups = defaultdict(list)
    for r in rows:
        groups[r["size"]].append(r)

    result = []
    for size in sorted(groups):
        group = groups[size]
        fields = [k for k in group[0] if isinstance(group[0][k], (int, float)) and k != "size"]
        agg = {"size": size, "n_seeds": len(group)}
        for f in fields:
            vals = [r[f] for r in group]
            agg[f + "_mean"] = statistics.mean(vals)
            agg[f + "_std"]  = statistics.stdev(vals) if len(vals) > 1 else 0.0
            agg[f + "_ci95"] = ci95(vals)
        result.append(agg)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-ids", default="h2h_s42,h2h_s123,h2h_s999")
    parser.add_argument("--out-id", default="h2h_aggregate")
    args = parser.parse_args()
    run_ids = [r.strip() for r in args.run_ids.split(",")]
    rows = load_rows(run_ids)
    agg = aggregate(rows)
    out_dir = os.path.join("results", args.out_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "h2h_aggregate.json")
    with open(out_path, "w") as f:
        json.dump({"run_ids": run_ids, "rows": agg}, f, indent=2)
    print(json.dumps({"output": out_path}, indent=2))
    # Print human-readable table
    print(f"\n{'Size':>10}  {'LS commit (ms)':>16}  {'TR commit (ms)':>16}  {'IM commit (ms)':>16}  {'LS verify p50 (ms)':>20}  {'TR verify p50 (ms)':>20}")
    for r in agg:
        print(f"{r['size']:>10,}  "
              f"{r['ls_commit_ms_mean']:>12.1f}±{r['ls_commit_ms_ci95']:.1f}  "
              f"{r['tr_commit_ms_mean']:>12.1f}±{r['tr_commit_ms_ci95']:.1f}  "
              f"{r['im_commit_ms_mean']:>12.1f}±{r['im_commit_ms_ci95']:.1f}  "
              f"{r['ls_verify_p50_ms_mean']:>16.4f}±{r['ls_verify_p50_ms_ci95']:.4f}  "
              f"{r['tr_verify_p50_ms_mean']:>16.4f}±{r['tr_verify_p50_ms_ci95']:.4f}")

if __name__ == "__main__":
    main()
