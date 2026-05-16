import json
import os
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Dict, List, Tuple

from common import ensure_parent_dir
from merkle_signed_log import MerkleCommitment


def _canonical(payload: Dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(payload: bytes) -> str:
    return sha256(payload).hexdigest()


@dataclass
class AnchorRecord:
    sequence: int
    timestamp: int
    commitment_hash: str
    tree_size: int
    root_hash: str
    previous_anchor_hash: str
    anchor_hash: str

    def to_dict(self) -> Dict:
        return asdict(self)


class WitnessAnchorLog:
    """Append-only local witness log for signed tree-head anchoring.

    This is not a consensus system and does not claim public timestamping.
    It models the small independent witness needed to make storage rollback
    detectable: if storage returns an older commitment, the auditor can compare
    it with the witness's latest anchored sequence and root.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def load(self) -> List[AnchorRecord]:
        if not os.path.exists(self.path):
            return []
        out: List[AnchorRecord] = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                payload = json.loads(line)
                out.append(AnchorRecord(**payload))
        return out

    def append(self, commitment: MerkleCommitment, timestamp: int = None) -> AnchorRecord:
        records = self.load()
        previous = records[-1].anchor_hash if records else "0" * 64
        commitment_payload = commitment.to_dict()
        commitment_hash = _sha256_hex(_canonical(commitment_payload))
        body = {
            "sequence": len(records) + 1,
            "timestamp": int(time.time()) if timestamp is None else int(timestamp),
            "commitment_hash": commitment_hash,
            "tree_size": commitment.tree_size,
            "root_hash": commitment.root_hash,
            "previous_anchor_hash": previous,
        }
        body["anchor_hash"] = _sha256_hex(_canonical(body))
        record = AnchorRecord(**body)
        ensure_parent_dir(self.path)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        return record

    def verify_chain(self) -> bool:
        previous = "0" * 64
        for expected_sequence, record in enumerate(self.load(), start=1):
            if record.sequence != expected_sequence or record.previous_anchor_hash != previous:
                return False
            body = record.to_dict()
            anchor_hash = body.pop("anchor_hash")
            if _sha256_hex(_canonical(body)) != anchor_hash:
                return False
            previous = anchor_hash
        return True

    def detect_rollback(self, commitment: MerkleCommitment) -> Tuple[bool, str]:
        records = self.load()
        if not records:
            return False, "no_anchor"
        latest = records[-1]
        commitment_hash = _sha256_hex(_canonical(commitment.to_dict()))
        if commitment_hash == latest.commitment_hash:
            return False, "matches_latest_anchor"
        if commitment.tree_size < latest.tree_size:
            return True, "commitment_older_than_witness"
        for record in records:
            if record.commitment_hash == commitment_hash:
                return True, "stale_but_known_anchor"
        return True, "unanchored_commitment"
