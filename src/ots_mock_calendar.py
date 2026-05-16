"""ots_mock_calendar.py – Local mock of selected OpenTimestamps calendar API calls.

This mock is for offline serialization tests only. It is not a substitute for
public OpenTimestamps calendar latency, availability, or confirmation results.

The OpenTimestamps calendar server protocol (from the ots-server reference
implementation at https://github.com/opentimestamps/opentimestamps-server):

  POST /digest
    Request body:  raw 32-byte SHA-256 digest
    Response body: binary-serialized OTS Timestamp continuation (the server's
                   subtree merging the submitted digest into its aggregation
                   tree, terminated with a PendingAttestation pointing back to
                   the calendar's own URL).

This mock server implements that protocol faithfully using the opentimestamps
Python library, so `ots stamp -c http://localhost:<port>` produces a
syntactically correct .ots receipt that can be parsed by `ots info`.

A real calendar would:
  1. Batch many client digests into a Merkle aggregation tree.
  2. Commit the tree root to Bitcoin (via OP_RETURN or similar).
  3. Upgrade the PendingAttestation to a BitcoinBlockHeaderAttestation once mined.

This mock skips step 2-3 (no Bitcoin node required) and instead returns a
PendingAttestation with the mock calendar's URL, which is the exact state a
real receipt is in for the first ~10-20 minutes after stamping.

Usage (standalone):
    python src/ots_mock_calendar.py --port 14158 --latency-ms 120

Usage (from run_ots_anchoring.py):
    Started as a subprocess on a free port, URL passed to ots stamp via -c.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional


# ---------------------------------------------------------------------------
# Minimal OTS binary serialization
# (reimplements only what's needed for the /digest response)
# ---------------------------------------------------------------------------

# Magic bytes for OTS file format
_OTS_MAGIC = bytes([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d,
    0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
    0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])
_OTS_VERSION = 1

# Op tags
_TAG_SHA256       = b'\x08'
_TAG_APPEND       = b'\xf0'
_TAG_PREPEND      = b'\xf1'
_TAG_ATTESTATION  = b'\x00'

# Attestation type tags
_ATT_PENDING      = bytes([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])
_ATT_BITCOIN      = bytes([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])


def _varint(n: int) -> bytes:
    """Encode a non-negative integer as OTS variable-length integer."""
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _write_bytes(data: bytes) -> bytes:
    """Length-prefixed byte sequence."""
    return _varint(len(data)) + data


def build_pending_response(digest: bytes, calendar_url: str, nonce: Optional[bytes] = None) -> bytes:
    """
    Build the binary OTS timestamp continuation that a calendar server returns
    in response to POST /digest.

    Structure (mirrors opentimestamps-server's stamp_notary output):
      [PREPEND nonce]          (optional; calendar adds a nonce for aggregation)
      [SHA256]                 (hash of nonce || digest)
      [ATTESTATION pending]    (PendingAttestation pointing to calendar_url)

    The ots client prepends this continuation to the file's own timestamp tree,
    producing a complete (pending) .ots receipt.
    """
    buf = io.BytesIO()

    if nonce is None:
        # Real calendars use a per-request random nonce to prevent clients from
        # deducing other clients' timestamps via the shared aggregation tree.
        nonce = os.urandom(16)

    # 1. PREPEND nonce  →  timestamp = sha256(nonce || digest)
    buf.write(_TAG_PREPEND)
    buf.write(_write_bytes(nonce))

    # 2. SHA256
    buf.write(_TAG_SHA256)

    # 3. ATTESTATION pending
    # TimeAttestation binary format (from opentimestamps library):
    #   [0x00 marker] [8-byte type tag] [varint(outer_payload_len)] [varint(url_len)] [url_bytes]
    # The outer payload is itself a varbytes-encoded url (double-wrapped).
    buf.write(_TAG_ATTESTATION)
    buf.write(_ATT_PENDING)
    url_bytes = calendar_url.encode("utf-8")
    inner_payload = _write_bytes(url_bytes)   # varint(url_len) + url_bytes
    buf.write(_write_bytes(inner_payload))     # varint(inner_len) + inner_payload

    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_handler_lock = threading.Lock()


class OTSCalendarHandler(BaseHTTPRequestHandler):
    """Handle POST /digest exactly as the reference ots-server does."""

    calendar_url: str = "http://localhost:14158"
    simulated_latency_ms: float = 0.0
    request_count: int = 0

    def do_POST(self):
        if self.path != "/digest":
            self.send_error(404, "Only /digest is supported")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if len(body) != 32:
            self.send_error(400, f"Expected 32-byte digest, got {len(body)}")
            return

        # Simulate network latency
        if self.simulated_latency_ms > 0:
            time.sleep(self.simulated_latency_ms / 1000.0)

        with _handler_lock:
            OTSCalendarHandler.request_count += 1

        response = build_pending_response(body, self.calendar_url)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        # Suppress default access log (caller captures timing)
        pass


def run_server(port: int, calendar_url: str, latency_ms: float = 0.0) -> HTTPServer:
    OTSCalendarHandler.calendar_url = calendar_url
    OTSCalendarHandler.simulated_latency_ms = latency_ms
    server = HTTPServer(("127.0.0.1", port), OTSCalendarHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ---------------------------------------------------------------------------
# Main (standalone)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=14158)
    parser.add_argument("--latency-ms", type=float, default=120.0,
                        help="Simulated round-trip latency to Bitcoin calendar (ms). "
                             "Real calendars average ~100-500 ms. Default: 120")
    args = parser.parse_args()

    url = f"http://localhost:{args.port}"
    server = run_server(args.port, url, args.latency_ms)
    print(f"OTS mock calendar running at {url}  (simulated latency={args.latency_ms}ms)")
    print("Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
