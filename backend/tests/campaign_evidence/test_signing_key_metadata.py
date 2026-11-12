"""
TDD tests for SigningKeyMetadata DB model.

Tests verify:
- Table has all required columns
- Default status is PENDING
- Unique constraint on key_id
"""

import uuid
import pytest
from sqlalchemy import inspect

from app.db.models.signing_key_metadata import SigningKeyMetadata


def test_signing_key_metadata_table_columns(db_session):
    """All required columns exist on the signing_key_metadata table."""
    inspector = inspect(db_session.bind)
    columns = {col["name"] for col in inspector.get_columns("signing_key_metadata")}

    required = {
        "id",
        "key_id",
        "algorithm",
        "status",
        "public_key_pem",
        "public_key_fingerprint",
        "encrypted_private_key",
        "created_at",
        "activated_at",
        "retired_at",
        "key_metadata",
    }
    missing = required - columns
    assert not missing, f"Missing columns: {missing}"


def test_signing_key_metadata_default_status_pending(db_session):
    """A newly created key metadata has status='PENDING' by default."""
    key_metadata = SigningKeyMetadata(
        key_id="test-key-" + uuid.uuid4().hex[:16],
        algorithm="ed25519",
        public_key_pem="-----BEGIN PUBLIC KEY-----\nMHcwDQYJKoZIhvcNAQEBBQADVgAwU...\n-----END PUBLIC KEY-----",
        public_key_fingerprint="a" * 64,
        encrypted_private_key="gAAAAABlTc5c...",
    )
    db_session.add(key_metadata)
    db_session.commit()
    db_session.refresh(key_metadata)

    assert key_metadata.status == "PENDING"


def test_signing_key_metadata_key_id_unique(db_session):
    """Duplicate key_id raises IntegrityError."""
    from sqlalchemy import exc

    key_id = "test-key-" + uuid.uuid4().hex[:16]

    key1 = SigningKeyMetadata(
        key_id=key_id,
        algorithm="ed25519",
        public_key_pem="-----BEGIN PUBLIC KEY-----\nMHcwDQYJKoZIhvcNAQEBBQADVgAwU...\n-----END PUBLIC KEY-----",
        public_key_fingerprint="b" * 64,
        encrypted_private_key="gAAAAABlTc5c...",
    )
    db_session.add(key1)
    db_session.commit()

    key2 = SigningKeyMetadata(
        key_id=key_id,
        algorithm="ed25519",
        public_key_pem="-----BEGIN PUBLIC KEY-----\nMHcwDQYJKoZIhvcNAQEBBQADVgAwU...\n-----END PUBLIC KEY-----",
        public_key_fingerprint="c" * 64,
        encrypted_private_key="gAAAAABlTc5d...",
    )
    db_session.add(key2)

    with pytest.raises(exc.IntegrityError):
        db_session.commit()
