"""docs/trust.md's scope table must match the code (regenerate with python -m tools.gen_scopes_doc --write)."""

from app.services.microsoft_oauth_scopes import DELEGATED_SCOPES, PREVIEW_SCOPES, WRITE_SCOPES
from tools.gen_scopes_doc import TRUST_DOC, replace_block


def test_trust_doc_scope_table_is_current():
    text = TRUST_DOC.read_text(encoding="utf-8")
    assert (
        replace_block(text) == text
    ), "docs/trust.md is stale: run `python -m tools.gen_scopes_doc --write` in backend/"


def test_every_readwrite_scope_is_classified_as_write():
    readwrite = {s for s in DELEGATED_SCOPES if ".ReadWrite." in s}
    assert readwrite <= WRITE_SCOPES
    assert "User.ReadWrite.All" in WRITE_SCOPES


def test_preview_requests_no_write_scope():
    assert not set(PREVIEW_SCOPES) & WRITE_SCOPES
