import random
from decimal import Decimal
from typing import List

from common import Event


class AttackSuite:
    @staticmethod
    def insert(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 1)
        out = events[:]
        idx = random.randint(0, len(out))
        out.insert(
            idx,
            Event(
                event_id=999999,
                timestamp=events[idx - 1].timestamp if idx > 0 else events[0].timestamp,
                account_id="ACC-ATTACK",
                amount="7777.77",
                currency="USD",
                event_type="TRANSFER",
                reference="REF-ATTACK-INSERT",
            ),
        )
        return out

    @staticmethod
    def delete(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 2)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        del out[idx]
        return out

    @staticmethod
    def modify(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 3)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        target = out[idx]
        out[idx] = Event(
            event_id=target.event_id,
            timestamp=target.timestamp,
            account_id=target.account_id,
            amount=str((Decimal(target.amount) * Decimal("1.5")).quantize(Decimal("0.01"))),
            currency=target.currency,
            event_type=target.event_type,
            reference=target.reference + "-MOD",
        )
        return out

    @staticmethod
    def replay(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 4)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        out.append(out[idx])
        return out

    @staticmethod
    def truncate(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 5)
        if len(events) < 2:
            return events[:]
        cut = random.randint(1, len(events) - 1)
        return events[:cut]
