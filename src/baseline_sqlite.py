import json
import os
import sqlite3
from dataclasses import dataclass
from hashlib import sha256
from typing import List, Tuple

from common import Event


def _sha256_hex(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class SQLiteAuditCommitment:
    db_path: str
    head_hash: str
    row_count: int


class SQLiteAuditBaseline:
    """SQLite audit table with a trigger-like hash chain.

    The benchmark uses explicit Python inserts so it remains portable
    across SQLite builds. The schema mirrors a common deployment pattern:
    rows are persisted in a relational table and each row carries the
    previous row's hash plus its own row hash.
    """

    @staticmethod
    def build(events: List[Event], db_path: str) -> SQLiteAuditCommitment:
        if os.path.exists(db_path):
            os.remove(db_path)
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                CREATE TABLE audit_events (
                    seq INTEGER PRIMARY KEY,
                    canonical_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    row_hash TEXT NOT NULL
                )
                """
            )
            prev = "GENESIS"
            for seq, event in enumerate(events, start=1):
                canonical = event.canonical_json()
                row_hash = _sha256_hex(json.dumps([seq, prev, canonical], separators=(",", ":")))
                conn.execute(
                    "INSERT INTO audit_events(seq, canonical_json, prev_hash, row_hash) VALUES (?, ?, ?, ?)",
                    (seq, canonical, prev, row_hash),
                )
                prev = row_hash
            conn.commit()
            return SQLiteAuditCommitment(db_path=db_path, head_hash=prev, row_count=len(events))
        finally:
            conn.close()

    @staticmethod
    def verify(events: List[Event], commitment: SQLiteAuditCommitment) -> Tuple[bool, int]:
        if len(events) != commitment.row_count or not os.path.exists(commitment.db_path):
            return False, 32
        conn = sqlite3.connect(commitment.db_path)
        try:
            rows = conn.execute(
                "SELECT seq, canonical_json, prev_hash, row_hash FROM audit_events ORDER BY seq"
            ).fetchall()
        finally:
            conn.close()
        if len(rows) != len(events):
            return False, 32
        prev = "GENESIS"
        for expected_seq, (seq, canonical, prev_hash, row_hash) in enumerate(rows, start=1):
            if seq != expected_seq or prev_hash != prev:
                return False, 32
            if canonical != events[expected_seq - 1].canonical_json():
                return False, 32
            expected_hash = _sha256_hex(json.dumps([seq, prev_hash, canonical], separators=(",", ":")))
            if expected_hash != row_hash:
                return False, 32
            prev = row_hash
        return prev == commitment.head_hash, 32
