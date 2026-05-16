from dataclasses import dataclass
from typing import List, Tuple

from common import Event, sha256_hex


@dataclass
class HashChainCommitment:
    head_hash: str
    chain: List[str]


class HashChainBaseline:
    @staticmethod
    def build_chain(events: List[Event]) -> HashChainCommitment:
        prev = "GENESIS"
        chain: List[str] = []
        for e in events:
            prev = sha256_hex(prev + "|" + e.canonical_json())
            chain.append(prev)
        return HashChainCommitment(head_hash=prev, chain=chain)

    @staticmethod
    def verify(events: List[Event], commitment: HashChainCommitment) -> Tuple[bool, int]:
        rebuilt = HashChainBaseline.build_chain(events)
        return rebuilt.head_hash == commitment.head_hash, 32
