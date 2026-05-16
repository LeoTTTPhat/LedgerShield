import argparse
import csv
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from common import Event, write_json


SOURCE_URL = "https://raw.githubusercontent.com/dnoeth/1999_Czech_financial_dataset_Teradata/master/fin_trans.tsv"


def _timestamp(date_s: str) -> int:
    return int(datetime.strptime(date_s, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())


def _row_to_event(row: List[str], index: int) -> Event:
    # fin_trans.tsv columns:
    # trans_id, account_id, date, amount, balance, type, operation,
    # k_symbol, bank, account. Some optional trailing fields are blank.
    fields = row + [""] * (10 - len(row))
    trans_id, account_id, date_s, amount, balance, tx_type, operation, k_symbol, bank, other_account = fields[:10]
    event_type = "|".join(x for x in [tx_type, operation, k_symbol] if x.strip()) or "UNKNOWN"
    reference_parts = [f"trans={trans_id}", f"balance={balance}"]
    if bank.strip():
        reference_parts.append(f"bank={bank.strip()}")
    if other_account.strip():
        reference_parts.append(f"counterparty={other_account.strip()}")
    return Event(
        event_id=index,
        timestamp=_timestamp(date_s),
        account_id=f"BERKA-{account_id}",
        amount=amount,
        currency="CZK",
        event_type=event_type,
        reference=";".join(reference_parts),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--out-dir", default=os.path.join("data", "berka"))
    args = parser.parse_args()
    if args.num_events <= 0:
        raise ValueError("--num-events must be > 0")

    os.makedirs(args.out_dir, exist_ok=True)
    events: List[Event] = []
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "LedgerShield-artifact/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        decoded = (line.decode("utf-8", errors="replace") for line in response)
        reader = csv.reader(decoded, delimiter="\t")
        for row in reader:
            if len(events) >= args.num_events:
                break
            if not row:
                continue
            events.append(_row_to_event(row, len(events) + 1))

    events_path = os.path.join(args.out_dir, "events.jsonl")
    with open(events_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(event.canonical_json() + "\n")

    manifest: Dict = {
        "source": "PKDD'99 / Berka Czech financial dataset, Teradata TSV mirror",
        "source_url": SOURCE_URL,
        "description": "Real anonymized Czech bank transactions, modified in the Teradata mirror with shifted dates and scaled amounts.",
        "events_written": len(events),
        "events_path": events_path,
        "fetched_at_unix": int(time.time()),
        "schema": {
            "event_id": "1-based row index in the fetched subset",
            "timestamp": "transaction date at UTC midnight",
            "account_id": "BERKA-<account_id>",
            "amount": "transaction amount in CZK as provided by the Teradata mirror",
            "currency": "CZK",
            "event_type": "type|operation|k_symbol when present",
            "reference": "trans=<trans_id>;balance=<balance>;optional counterparty fields",
        },
    }
    manifest_path = os.path.join(args.out_dir, "manifest.json")
    write_json(manifest_path, manifest)
    print(json.dumps({"events_path": events_path, "manifest_path": manifest_path}, indent=2))


if __name__ == "__main__":
    main()
