import json
from hashlib import sha256
from hmac import compare_digest, new
from secrets import token_bytes
from typing import Any


_ATTESTATION_KEY = token_bytes(32)
_SIGNED_FIELDS = (
    "source_id",
    "parser",
    "raw_line_count",
    "parsed_event_count",
    "finding_count",
    "incident_count",
    "live_retention",
    "events",
    "findings",
    "incidents",
    "evidence",
)


def attest_live_snapshot(snapshot: Any) -> str:
    return new(_ATTESTATION_KEY, _canonical_snapshot(snapshot), sha256).hexdigest()


def verify_live_snapshot_attestation(snapshot: Any) -> None:
    supplied = getattr(snapshot, "live_snapshot_attestation", None)
    if not supplied:
        raise ValueError("Live snapshot is missing its server attestation.")
    expected = attest_live_snapshot(snapshot)
    if not compare_digest(expected, supplied):
        raise ValueError("Live snapshot attestation is invalid or the snapshot was modified.")


def _canonical_snapshot(snapshot: Any) -> bytes:
    payload = snapshot.model_dump(mode="json")
    signed_payload = {field: payload.get(field) for field in _SIGNED_FIELDS}
    return json.dumps(
        signed_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
