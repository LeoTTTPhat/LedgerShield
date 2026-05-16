from typing import List, Tuple

from common import Event, sha256_hex


class AppendOnlyCSVBaseline:
    @staticmethod
    def commit(events: List[Event]) -> str:
        # Baseline "commitment" is a single digest over full ordered content.
        material = "".join([e.canonical_json() for e in events])
        return sha256_hex(material)

    @staticmethod
    def verify(events: List[Event], committed_digest: str) -> Tuple[bool, int]:
        current = AppendOnlyCSVBaseline.commit(events)
        return current == committed_digest, 0
