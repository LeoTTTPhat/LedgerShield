import csv
import hashlib
import json
import os
import random
from decimal import Decimal
from dataclasses import dataclass, asdict
from typing import Dict, List


@dataclass
class Event:
    event_id: int
    timestamp: int
    account_id: str
    amount: str
    currency: str
    event_type: str
    reference: str

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_events_csv(path: str, events: List[Event]) -> None:
    ensure_parent_dir(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(events[0]).keys()))
        writer.writeheader()
        for e in events:
            writer.writerow(asdict(e))


def read_events_csv(path: str) -> List[Event]:
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        out: List[Event] = []
        for row in reader:
            out.append(
                Event(
                    event_id=int(row["event_id"]),
                    timestamp=int(row["timestamp"]),
                    account_id=row["account_id"],
                    amount=row["amount"],
                    currency=row["currency"],
                    event_type=row["event_type"],
                    reference=row["reference"],
                )
            )
    return out


def generate_synthetic_events(num_events: int, seed: int) -> List[Event]:
    random.seed(seed)
    # Deterministic timestamps derived only from seed and index.
    base_ts = 1700000000 + (seed % 100000)
    types = ["DEPOSIT", "WITHDRAWAL", "TRANSFER", "FEE"]
    currencies = ["USD", "EUR", "VND"]
    events = []
    for i in range(num_events):
        event = Event(
            event_id=i + 1,
            timestamp=base_ts + i,
            account_id=f"ACC-{random.randint(10000, 99999)}",
            amount=str(Decimal(random.randrange(100, 500000)) / Decimal("100")),
            currency=random.choice(currencies),
            event_type=random.choice(types),
            reference=f"REF-{random.randint(100000, 999999)}",
        )
        events.append(event)
    return events


def generate_calibrated_financial_events(num_events: int, seed: int) -> List[Event]:
    """Generate a deterministic public-style financial audit workload.

    The workload is calibrated to common transaction-log properties rather
    than sampled from private data: Zipf-like account skew, heavy-tailed
    amounts, bursty timestamps, and a transfer-heavy event mix.
    """
    rng = random.Random(seed)
    base_ts = 1700000000 + (seed % 100000)
    event_types = ["TRANSFER", "DEPOSIT", "WITHDRAWAL", "FEE", "REVERSAL", "AML_ALERT"]
    weights = [0.52, 0.18, 0.16, 0.09, 0.03, 0.02]
    currencies = ["USD", "EUR", "VND"]
    currency_weights = [0.62, 0.18, 0.20]
    hot_accounts = [f"ACC-{10000 + i}" for i in range(100)]
    cold_accounts = [f"ACC-{20000 + i}" for i in range(10000)]
    events: List[Event] = []
    ts = base_ts
    for i in range(num_events):
        if i % max(1, num_events // 20) == 0:
            ts += rng.randint(30, 300)
        else:
            ts += rng.choice([0, 0, 1, 1, 2, 5])
        account = rng.choice(hot_accounts) if rng.random() < 0.78 else rng.choice(cold_accounts)
        event_type = rng.choices(event_types, weights=weights, k=1)[0]
        currency = rng.choices(currencies, weights=currency_weights, k=1)[0]
        # Log-normal cents, capped to avoid unrealistic million-dollar retail events.
        cents = min(int(rng.lognormvariate(5.2, 1.15) * 100), 25_000_000)
        if event_type == "FEE":
            cents = min(cents, 25_00)
        elif event_type == "AML_ALERT":
            cents = 0
        amount = str(Decimal(max(cents, 0)) / Decimal("100"))
        events.append(
            Event(
                event_id=i + 1,
                timestamp=ts,
                account_id=account,
                amount=amount,
                currency=currency,
                event_type=event_type,
                reference=f"CAL-{seed}-{i + 1:08d}",
            )
        )
    return events


def generate_events(num_events: int, seed: int, workload: str = "synthetic") -> List[Event]:
    if workload == "synthetic":
        return generate_synthetic_events(num_events, seed)
    if workload == "calibrated":
        return generate_calibrated_financial_events(num_events, seed)
    raise ValueError(f"unknown workload: {workload}")


def read_events_jsonl(path: str, limit: int = None) -> List[Event]:
    events: List[Event] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if limit is not None and len(events) >= limit:
                break
            if not line.strip():
                continue
            row = json.loads(line)
            events.append(
                Event(
                    event_id=int(row["event_id"]),
                    timestamp=int(row["timestamp"]),
                    account_id=str(row["account_id"]),
                    amount=str(row["amount"]),
                    currency=str(row["currency"]),
                    event_type=str(row["event_type"]),
                    reference=str(row["reference"]),
                )
            )
    return events


def file_size(path: str) -> int:
    return os.path.getsize(path)


def write_json(path: str, payload: Dict) -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
