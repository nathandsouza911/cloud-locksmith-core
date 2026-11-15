"""The release version must be the same everywhere a user or a bug report reads it."""

import json
import re
from pathlib import Path

from app.main import APP_VERSION

ROOT = Path(__file__).resolve().parents[2]


def test_readme_status_matches_app_version():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"^Status: \*\*([0-9.]+)\*\*", readme, re.M)
    assert match, "README.md has no 'Status: **x.y.z**' line"
    assert match.group(1) == APP_VERSION


def test_compose_images_pin_app_version():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    tags = re.findall(r"image: ghcr\.io/[^:\s]+:([^\s]+)", compose)
    assert tags, "docker-compose.yml pins no ghcr.io images"
    assert set(tags) == {APP_VERSION}


def test_dashboard_package_version_matches():
    package = json.loads((ROOT / "dashboard" / "package.json").read_text(encoding="utf-8"))
    assert package["version"] == APP_VERSION


def test_root_endpoint_reports_app_version():
    from fastapi.testclient import TestClient

    from app.main import app

    assert app.version == APP_VERSION
    assert TestClient(app).get("/").json()["version"] == APP_VERSION
