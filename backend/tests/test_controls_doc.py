"""docs/controls.md must match the control registry (regenerate with python -m tools.gen_controls_doc)."""

from pathlib import Path

from tools.gen_controls_doc import render

DOC = Path(__file__).resolve().parents[2] / "docs" / "controls.md"


def test_controls_doc_is_up_to_date():
    assert (
        DOC.read_text(encoding="utf-8") == render()
    ), "docs/controls.md is stale: run `python -m tools.gen_controls_doc > ../docs/controls.md` in backend/"
