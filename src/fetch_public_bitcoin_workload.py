import argparse
import json
import os
import time
import urllib.request
from decimal import Decimal
from typing import Dict, List

from common import Event, write_json


API_BASE = "https://blockstream.info/api"


def _get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "LedgerShield-artifact/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "LedgerShield-artifact/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8").strip()


def _tx_pages(block_hash: str, limit: int) -> List[Dict]:
    txs: List[Dict] = []
    start = 0
    while len(txs) < limit:
        page = _get_json(f"{API_BASE}/block/{block_hash}/txs/{start}")
        if not page:
            break
        txs.extend(page)
        start += len(page)
        time.sleep(0.05)
    return txs[:limit]


def _tx_to_event(tx: Dict, event_id: int, block_time: int) -> Event:
    outputs = tx.get("vout", [])
    output_value = sum(int(o.get("value", 0)) for o in outputs)
    first_address = next((o.get("scriptpubkey_address") for o in outputs if o.get("scriptpubkey_address")), None)
    amount_btc = Decimal(output_value) / Decimal("100000000")
    return Event(
        event_id=event_id,
        timestamp=block_time,
        account_id=first_address or f"NOADDR-{tx['txid'][:16]}",
        amount=format(amount_btc, "f"),
        currency="BTC",
        event_type="BITCOIN_TX",
        reference=tx["txid"],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--block-hash", default="")
    parser.add_argument("--out-dir", default=os.path.join("data", "public_bitcoin"))
    args = parser.parse_args()
    if args.num_events <= 0:
        raise ValueError("--num-events must be > 0")

    os.makedirs(args.out_dir, exist_ok=True)
    block_hash = args.block_hash or _get_text(f"{API_BASE}/blocks/tip/hash")
    block = _get_json(f"{API_BASE}/block/{block_hash}")
    txs = _tx_pages(block_hash, args.num_events)
    events = [_tx_to_event(tx, i + 1, int(block["timestamp"])) for i, tx in enumerate(txs)]

    events_path = os.path.join(args.out_dir, "events.jsonl")
    with open(events_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(event.canonical_json() + "\n")

    manifest = {
        "source": "Blockstream Esplora public Bitcoin API",
        "api_base": API_BASE,
        "block_hash": block_hash,
        "block_height": block.get("height"),
        "block_timestamp": block.get("timestamp"),
        "block_tx_count": block.get("tx_count"),
        "events_written": len(events),
        "events_path": events_path,
        "schema": {
            "event_id": "1-based transaction index within fetched subset",
            "timestamp": "Bitcoin block timestamp",
            "account_id": "first output address when present, otherwise NOADDR-<txid prefix>",
            "amount": "sum of transaction outputs in BTC",
            "currency": "BTC",
            "event_type": "BITCOIN_TX",
            "reference": "Bitcoin transaction id",
        },
    }
    manifest_path = os.path.join(args.out_dir, "manifest.json")
    write_json(manifest_path, manifest)
    print(json.dumps({"events_path": events_path, "manifest_path": manifest_path}, indent=2))


if __name__ == "__main__":
    main()
