import hashlib
import json
from datetime import date, datetime
from typing import Optional

from sqlalchemy import desc, text
from sqlalchemy.orm import Session

from app.db.models.report_payload import ReportPayload
from app.services.report_attestation_service import build_attestation, sign_attestation

# Sentinel written as previous_report_hash for the first report in a chain.
# Stored as a literal string so it participates in the chain_hash computation
# identically to any real hash value.
_CHAIN_GENESIS = "GENESIS"


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _canonical_json(data: dict) -> str:
    """Deterministic JSON serialization used for content_hash computation.

    sort_keys ensures key ordering is stable across Python versions.
    default=str converts non-JSON types (datetime, Decimal, etc.) to their
    string representation — matching what Postgres stores in JSONB and
    what any downstream verifier must apply before re-hashing.
    """
    return json.dumps(data, sort_keys=True, default=str, ensure_ascii=True)


def compute_content_hash(data: dict) -> str:
    """SHA-256 of the canonical JSON serialization of a report dict."""
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _compute_chain_hash(
    *,
    content_hash: str,
    previous_report_hash: str,
    tenant_id: str,
    generated_at: datetime,
) -> str:
    """SHA-256 over the pipe-delimited chain payload.

    Formula (field order is fixed — never reorder):
        chain_hash = SHA256(content_hash | previous_report_hash | tenant_id | generated_at_iso)

    The pipe separator prevents value-boundary ambiguity (e.g. a tenant_id
    that ends with the first character of generated_at cannot collide with
    a different split).
    """
    payload = "|".join(
        [
            content_hash,
            previous_report_hash,
            tenant_id,
            generated_at.isoformat(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------


def archive_report(
    db: Session,
    *,
    tenant_id: str,
    report_type: str,
    report_data: dict,
    score: Optional[int] = None,
) -> ReportPayload:
    """Serialize, hash, chain-link, and persist a report payload.

    Write sequence (all within the caller's transaction):
      1. Acquire a transaction-scoped advisory lock on (tenant_id, report_type).
         This serialises concurrent inserts for the same chain without the fork
         race inherent in SELECT FOR UPDATE: the second writer acquires the lock
         only after the first commits, so it always reads the just-committed row
         as its predecessor.
      2. INSERT the row with chain columns NULL — lets Postgres assign
         generated_at via server_default.
      3. flush() + refresh() to read the server-assigned generated_at.
      4. Compute chain_hash from (content_hash, previous_report_hash,
         tenant_id, generated_at).
      5. Build and sign the attestation object, then write all hash and
         attestation columns in a single flush().

    Caller is responsible for committing the session.
    """
    content_hash = compute_content_hash(report_data)

    # ── 1. Advisory lock: serialises all concurrent inserts for this chain.
    # pg_advisory_xact_lock is transaction-scoped — released automatically on
    # COMMIT or ROLLBACK.  A contending writer blocks here and, after the first
    # transaction commits, reads the newly committed row as its predecessor.
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"{tenant_id}:{report_type}"},
    )
    predecessor = (
        db.query(ReportPayload)
        .filter(
            ReportPayload.tenant_id == tenant_id,
            ReportPayload.report_type == report_type,
        )
        .order_by(desc(ReportPayload.id))
        .first()
    )
    previous_report_hash = (
        predecessor.chain_hash if predecessor is not None and predecessor.chain_hash is not None else _CHAIN_GENESIS
    )

    # ── 2. INSERT with chain columns absent — Postgres sets generated_at.
    entry = ReportPayload(
        tenant_id=tenant_id,
        report_type=report_type,
        # Normalise datetimes to strings before JSONB so stored value matches
        # the canonical JSON used in content_hash.
        payload=json.loads(_canonical_json(report_data)),
        content_hash=content_hash,
        score=score,
    )
    db.add(entry)
    db.flush()
    db.refresh(entry)  # read server-assigned generated_at into the ORM object

    # ── 3. Compute chain_hash using the actual DB timestamp.
    chain_hash = _compute_chain_hash(
        content_hash=content_hash,
        previous_report_hash=previous_report_hash,
        tenant_id=tenant_id,
        generated_at=entry.generated_at,
    )

    # ── 4. Write hash columns, build attestation, and flush the UPDATE.
    entry.previous_report_hash = previous_report_hash
    entry.chain_hash = chain_hash

    attestation = build_attestation(entry, report_data)
    entry.attestation_json = attestation
    entry.attestation_signature = sign_attestation(attestation)

    db.flush()

    return entry


# ---------------------------------------------------------------------------
# Read helpers (unchanged public API)
# ---------------------------------------------------------------------------


def get_report_by_date(
    db: Session,
    *,
    tenant_id: str,
    report_type: str,
    as_of: date,
) -> Optional[ReportPayload]:
    """Return the most recent archived report generated on or before as_of (UTC date)."""
    cutoff = datetime(as_of.year, as_of.month, as_of.day, 23, 59, 59)
    return (
        db.query(ReportPayload)
        .filter(
            ReportPayload.tenant_id == tenant_id,
            ReportPayload.report_type == report_type,
            ReportPayload.generated_at <= cutoff,
        )
        .order_by(ReportPayload.generated_at.desc())
        .first()
    )


def get_latest_archived_report(
    db: Session,
    *,
    tenant_id: str,
    report_type: str,
) -> Optional[ReportPayload]:
    return (
        db.query(ReportPayload)
        .filter(
            ReportPayload.tenant_id == tenant_id,
            ReportPayload.report_type == report_type,
        )
        .order_by(ReportPayload.generated_at.desc())
        .first()
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_report_chain(
    db: Session,
    *,
    tenant_id: str,
    report_type: str,
) -> dict:
    """Re-derive and validate every chain_hash for a tenant + report_type.

    Returns::

        {
            "valid": bool,
            "tenant_id": str,
            "report_type": str,
            "total": int,
            "verified": int,   # rows with a non-NULL chain_hash
            "legacy": int,     # rows written before chain tracking (NULL chain_hash)
            "errors": [
                {
                    "row_id": int,
                    "issue": str,
                    "expected": str | None,
                    "stored": str | None,
                }
            ],
        }

    Verification rules:
    - Rows with chain_hash=NULL are legacy pre-migration entries.  They are
      counted and skipped but do not cause valid=False.
    - For each verified row, compute_content_hash(row.payload) is re-derived and
      compared to the stored content_hash.  A mismatch means the payload was
      altered after archival.
    - The first verified row's previous_report_hash must equal GENESIS (legacy
      predecessor rows have no chain_hash to link from).
    - Each subsequent verified row's previous_report_hash must equal the
      chain_hash of the immediately preceding verified row.
    - The stored chain_hash must match the value re-derived from the row's
      own fields using _compute_chain_hash.
    - Verification continues past errors so all breaks are surfaced in one pass.
    """
    rows = (
        db.query(ReportPayload)
        .filter(
            ReportPayload.tenant_id == tenant_id,
            ReportPayload.report_type == report_type,
        )
        .order_by(ReportPayload.id.asc())
        .all()
    )

    errors: list[dict] = []
    legacy = 0
    verified = 0
    expected_previous = _CHAIN_GENESIS

    for row in rows:
        if row.chain_hash is None:
            # Legacy row — no hash to verify.  The next verified row is
            # expected to reference GENESIS because legacy rows contribute
            # nothing to the chain.
            legacy += 1
            continue

        verified += 1

        # ── Re-hash the stored payload and compare to content_hash.
        # Uses the identical canonical_json as the write path — any byte-level
        # change to payload that the JSONB layer preserves will be detected.
        if row.payload is not None:
            derived_content_hash = compute_content_hash(row.payload)
            if derived_content_hash != row.content_hash:
                errors.append(
                    {
                        "row_id": row.id,
                        "issue": "content_hash mismatch — payload may have been altered",
                        "expected": derived_content_hash,
                        "stored": row.content_hash,
                    }
                )

        # ── Check linkage to predecessor.
        if row.previous_report_hash != expected_previous:
            errors.append(
                {
                    "row_id": row.id,
                    "issue": ("previous_report_hash does not match the chain_hash of the " "preceding verified report"),
                    "expected": expected_previous,
                    "stored": row.previous_report_hash,
                }
            )

        # ── Re-derive chain_hash from stored field values.
        if row.generated_at is None:
            errors.append(
                {
                    "row_id": row.id,
                    "issue": "generated_at is NULL — cannot re-derive chain_hash",
                    "expected": None,
                    "stored": row.chain_hash,
                }
            )
            expected_previous = row.chain_hash
            continue

        derived = _compute_chain_hash(
            content_hash=row.content_hash,
            previous_report_hash=row.previous_report_hash or _CHAIN_GENESIS,
            tenant_id=row.tenant_id,
            generated_at=row.generated_at,
        )

        if derived != row.chain_hash:
            errors.append(
                {
                    "row_id": row.id,
                    "issue": "chain_hash mismatch — row may have been tampered with",
                    "expected": derived,
                    "stored": row.chain_hash,
                }
            )

        # Advance the pointer even on error to detect all breaks in one pass.
        expected_previous = row.chain_hash

    return {
        "valid": len(errors) == 0,
        "tenant_id": tenant_id,
        "report_type": report_type,
        "total": len(rows),
        "verified": verified,
        "legacy": legacy,
        "errors": errors,
    }
