"""Tests for the one-shot setup container (deploy/setup/cl_setup.py).

`az` is never run: every test injects a fake that records its calls.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "deploy" / "setup"))
sys.path.insert(0, str(REPO_ROOT / "backend" / "app" / "services"))

import cl_setup  # noqa: E402
from microsoft_oauth_scopes import DELEGATED_SCOPES  # noqa: E402

TENANT = "11111111-2222-4333-8444-555555555555"
APP_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CLIENT_SECRET = "Xy7~Q.abc=def-ghi_jkl"
NEW_SECRET = "Nw8~R.new=sec-ret_000"
GRAPH_SCOPES = [{"id": f"scope-id-{name}", "value": name} for name in DELEGATED_SCOPES] + [
    {"id": "scope-id-unused", "value": "Mail.Send"}
]
SECRET_KEYS = ("MICROSOFT_CLIENT_SECRET", "MICROSOFT_CLIENT_SECRET_KEY_ID", "MICROSOFT_CLIENT_SECRET_EXPIRES")


class FakeAz:
    """Records every call; answers like `az` for the commands setup uses."""

    def __init__(self, tenant=TENANT, creds=None, secret=CLIENT_SECRET):
        self.calls = []
        self.tenant = tenant
        self.creds = list(creds or [])
        self.secret = secret
        self.failures = {}
        self.resource_access_file = None
        self.existing_apps = []
        self.create_result = {"appId": APP_ID, "id": "object-id"}
        self.organization = {
            "value": [
                {
                    "id": tenant,
                    "displayName": "Contoso Ltd",
                    "verifiedDomains": [
                        {"name": "contoso.onmicrosoft.com", "isDefault": False},
                        {"name": "contoso.com", "isDefault": True},
                    ],
                    "technicalNotificationMails": ["it@contoso.com"],
                    "street": "1 Secret Street",
                }
            ]
        }

    def fail(self, *prefix, stderr="ERROR: boom"):
        self.failures[prefix] = cl_setup.AzError(stderr)

    def __call__(self, args, capture=True):
        self.calls.append((list(args), capture))
        for prefix, error in self.failures.items():
            if tuple(args[: len(prefix)]) == prefix:
                raise error
        cmd = tuple(args[:4])
        if args[0] in ("login", "logout"):
            return None
        if cmd[:2] == ("account", "show"):
            return {"tenantId": self.tenant, "user": {"name": "admin@example.com"}}
        if args[0] == "rest":
            assert args[args.index("--method") + 1] == "get"
            assert args[args.index("--url") + 1] == "https://graph.microsoft.com/v1.0/organization"
            return self.organization
        if cmd[:3] == ("ad", "sp", "show"):
            return GRAPH_SCOPES
        if cmd[:3] == ("ad", "app", "list"):
            name = args[args.index("--display-name") + 1]
            # Like az: a startswith() filter on the display name.
            return [dict(app) for app in self.existing_apps if app["displayName"].startswith(name)]
        if cmd[:3] == ("ad", "app", "create"):
            path = args[args.index("--required-resource-accesses") + 1]
            self.resource_access_file = json.loads(Path(path.lstrip("@")).read_text())
            return self.create_result
        if cmd[:3] == ("ad", "sp", "create"):
            return {"appId": APP_ID}
        if cmd == ("ad", "app", "credential", "list"):
            return [dict(c) for c in self.creds]
        if cmd == ("ad", "app", "credential", "reset"):
            key = f"key-{len(self.creds) + 1}"
            self.creds.append({"keyId": key, "endDateTime": "2028-11-18T10:00:00+00:00", "displayName": "setup"})
            return {"appId": APP_ID, "password": self.secret, "tenant": self.tenant}
        if cmd == ("ad", "app", "credential", "delete"):
            key = args[args.index("--key-id") + 1]
            self.creds = [c for c in self.creds if c["keyId"] != key]
            return None
        if cmd[:3] == ("ad", "app", "delete"):
            return None
        raise AssertionError(f"unexpected az call: {args}")

    def commands(self):
        return [" ".join(args) for args, _ in self.calls]

    def called(self, *prefix):
        return any(tuple(args[: len(prefix)]) == prefix for args, _ in self.calls)


def complete_config(**overrides):
    config = cl_setup.build_config(
        tenant_id=TENANT,
        client_id=APP_ID,
        client_secret=CLIENT_SECRET,
        secret_key_id="key-old",
        secret_expires="2027-01-01T00:00:00+00:00",
        local=cl_setup.generate_local_secrets(),
    )
    config.update(overrides)
    return config


def config_path(out_dir):
    return out_dir / "cloud-locksmith.env"


def db_path(out_dir):
    return out_dir / "cloud-locksmith-db.env"


def write_both(out_dir, config):
    cl_setup.write_config(db_path(out_dir), cl_setup.db_env(config))
    cl_setup.write_config(config_path(out_dir), config)


def assert_nothing_written(out_dir):
    assert not config_path(out_dir).exists()
    assert not (out_dir / "cloud-locksmith.env.tmp").exists()
    assert not db_path(out_dir).exists()
    assert not (out_dir / "cloud-locksmith-db.env.tmp").exists()


def test_render_parse_round_trip():
    config = complete_config(MICROSOFT_CLIENT_SECRET="a~b.c=d-e_f")
    text = cl_setup.render_env(config)
    assert text.startswith("# Generated by setup. Do not commit. Do not edit the secrets.\n")
    assert "\r" not in text and text.endswith("\n")
    assert "MICROSOFT_CLIENT_SECRET=a~b.c=d-e_f\n" in text
    assert cl_setup.parse_env(text) == config


def test_render_refuses_values_that_need_quoting():
    for bad in ("a b", "a\nb", "a$b", 'a"b', "a#b"):
        with pytest.raises(ValueError, match="MICROSOFT_CLIENT_SECRET") as excinfo:
            cl_setup.render_env(complete_config(MICROSOFT_CLIENT_SECRET=bad))
        assert bad not in str(excinfo.value)


def test_generated_secrets_distinct_and_fernet_valid():
    local = cl_setup.generate_local_secrets()
    assert set(local) == {
        "SESSION_SECRET",
        "APP_JWT_SECRET",
        "REPORT_SIGNING_SECRET",
        "ENCRYPTION_KEY",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
    }
    assert len(set(local.values())) == len(local)
    for key in ("SESSION_SECRET", "APP_JWT_SECRET", "REPORT_SIGNING_SECRET"):
        assert len(local[key]) >= 64
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
        assert len(local[key]) >= 43
    token = Fernet(local["ENCRYPTION_KEY"].encode()).encrypt(b"x")
    assert Fernet(local["ENCRYPTION_KEY"].encode()).decrypt(token) == b"x"
    assert cl_setup.generate_local_secrets() != local


def test_build_config_has_every_required_key_and_fixed_values():
    local = cl_setup.generate_local_secrets()
    config = cl_setup.build_config(
        tenant_id=TENANT,
        client_id=APP_ID,
        client_secret=CLIENT_SECRET,
        secret_key_id="key-1",
        secret_expires="2028-11-18T10:00:00+00:00",
        local=local,
    )
    assert cl_setup.missing_keys(config) == []
    assert set(config) == set(cl_setup.REQUIRED_KEYS)
    assert config["ENVIRONMENT"] == "production"
    assert config["LOCAL_LOOPBACK_ONLY"] == "true"
    assert config["ENABLE_SCHEDULER"] == "false"
    assert config["ENABLE_AUTO_REMEDIATION"] == "false"
    assert config["MICROSOFT_TENANT"] == TENANT
    assert config["MICROSOFT_CLIENT_ID"] == APP_ID
    assert config["MICROSOFT_CLIENT_SECRET"] == CLIENT_SECRET
    assert config["MICROSOFT_CLIENT_SECRET_KEY_ID"] == "key-1"
    assert config["MICROSOFT_CLIENT_SECRET_EXPIRES"] == "2028-11-18T10:00:00+00:00"
    assert config["BACKEND_PUBLIC_URL"] == "http://localhost:8000"
    assert config["FRONTEND_URL"] == "http://localhost:3000"
    assert config["CORS_ALLOWED_ORIGINS"] == "http://localhost:3000"
    assert config["MICROSOFT_REDIRECT_URI"] == "http://localhost:8000/api/v1/auth/microsoft/callback"
    assert config["DATABASE_URL"] == (
        f"postgresql://cloudlocksmith:{local['POSTGRES_PASSWORD']}@postgres:5432/cloudlocksmith"
    )
    assert config["REDIS_HOST"] == "redis"
    assert config["REDIS_PORT"] == "6379"
    assert config["REDIS_PASSWORD"] == local["REDIS_PASSWORD"]
    assert config["REPORT_SIGNING_SECRET"] != config["APP_JWT_SECRET"]


def test_build_config_rejects_non_guid_tenant():
    with pytest.raises(ValueError, match="tenant"):
        cl_setup.build_config(
            tenant_id="common",
            client_id=APP_ID,
            client_secret=CLIENT_SECRET,
            secret_key_id="k",
            secret_expires="e",
            local=cl_setup.generate_local_secrets(),
        )


def test_write_config_refuses_existing_file(tmp_path):
    path = config_path(tmp_path)
    path.write_bytes(b"EXISTING=1\n")
    with pytest.raises(FileExistsError):
        cl_setup.write_config(path, complete_config())
    assert path.read_bytes() == b"EXISTING=1\n"
    assert not (tmp_path / "cloud-locksmith.env.tmp").exists()


def test_write_config_writes_private_lf_file(tmp_path):
    path = config_path(tmp_path)
    config = complete_config()
    cl_setup.write_config(path, config)
    assert b"\r" not in path.read_bytes()
    assert cl_setup.parse_env(path.read_text()) == config
    assert not (tmp_path / "cloud-locksmith.env.tmp").exists()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_and_replace_give_the_file_to_the_out_dir_owner(tmp_path, monkeypatch):
    owner = os.stat(tmp_path)
    chowns = []
    monkeypatch.setattr(cl_setup.os, "chown", lambda p, uid, gid: chowns.append((Path(p), uid, gid)), raising=False)
    path = config_path(tmp_path)
    cl_setup.write_config(path, complete_config())
    cl_setup.replace_secret(path, client_secret="n", secret_key_id="k", secret_expires="e")
    assert chowns == [(path, owner.st_uid, owner.st_gid)] * 2


def test_chown_failure_is_ignored(tmp_path, monkeypatch):
    calls = []

    def refuse(p, uid, gid):
        calls.append(p)
        raise PermissionError("not permitted")

    monkeypatch.setattr(cl_setup.os, "chown", refuse, raising=False)
    path = config_path(tmp_path)
    cl_setup.write_config(path, complete_config())
    cl_setup.replace_secret(path, client_secret="n", secret_key_id="k", secret_expires="e")
    assert len(calls) == 2
    assert cl_setup.parse_env(path.read_text())["MICROSOFT_CLIENT_SECRET"] == "n"


def test_existing_complete_config_prints_status_and_makes_no_az_call(tmp_path, capsys):
    config = complete_config()
    write_both(tmp_path, config)
    before = config_path(tmp_path).read_bytes()
    db_before = db_path(tmp_path).read_bytes()
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    out, err = capsys.readouterr()
    assert az.calls == []
    assert TENANT in out and APP_ID in out and "2027-01-01T00:00:00+00:00" in out
    assert config_path(tmp_path).read_bytes() == before
    assert db_path(tmp_path).read_bytes() == db_before
    for key in ("MICROSOFT_CLIENT_SECRET", "SESSION_SECRET", "ENCRYPTION_KEY", "POSTGRES_PASSWORD"):
        assert config[key] not in out + err


def test_db_env_holds_only_the_two_service_passwords():
    config = complete_config()
    assert cl_setup.db_env(config) == {
        "POSTGRES_PASSWORD": config["POSTGRES_PASSWORD"],
        "REDIS_PASSWORD": config["REDIS_PASSWORD"],
    }


def test_missing_db_file_is_regenerated_from_the_main_config(tmp_path, capsys):
    config = complete_config()
    cl_setup.write_config(config_path(tmp_path), config)
    before = config_path(tmp_path).read_bytes()
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    out, err = capsys.readouterr()
    assert az.calls == []
    assert config_path(tmp_path).read_bytes() == before
    assert cl_setup.parse_env(db_path(tmp_path).read_text()) == cl_setup.db_env(config)
    assert "cloud-locksmith-db.env" in out + err
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "MICROSOFT_CLIENT_SECRET"):
        assert config[key] not in out + err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloud-locksmith-db.env", "cloud-locksmith.env"]


@pytest.mark.parametrize("db_text", ["POSTGRES_PASSWORD=other\nREDIS_PASSWORD=other\n", "not a config line\n", ""])
def test_db_file_that_disagrees_is_reported_and_left_unchanged(tmp_path, capsys, db_text):
    config = complete_config()
    cl_setup.write_config(config_path(tmp_path), config)
    db_path(tmp_path).write_text(db_text, newline="\n")
    before = config_path(tmp_path).read_bytes()
    db_before = db_path(tmp_path).read_bytes()
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 2
    out, err = capsys.readouterr()
    assert az.calls == []
    assert "cloud-locksmith-db.env" in err
    assert config_path(tmp_path).read_bytes() == before
    assert db_path(tmp_path).read_bytes() == db_before
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
        assert config[key] not in out + err


def test_db_file_without_main_config_is_refused_before_sign_in(tmp_path, capsys):
    db_path(tmp_path).write_text("POSTGRES_PASSWORD=x\nREDIS_PASSWORD=y\n", newline="\n")
    before = db_path(tmp_path).read_bytes()
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 2
    _, err = capsys.readouterr()
    assert az.calls == []
    assert "cloud-locksmith-db.env" in err
    assert db_path(tmp_path).read_bytes() == before
    assert not config_path(tmp_path).exists()


@pytest.mark.parametrize("argv", [[], ["--rotate-secret"]])
def test_partial_config_reports_missing_keys_and_changes_nothing(tmp_path, capsys, argv):
    config = complete_config()
    del config["ENCRYPTION_KEY"]
    config["REDIS_PASSWORD"] = ""
    path = config_path(tmp_path)
    path.write_text(cl_setup.render_env(config), newline="\n")
    before = path.read_bytes()
    az = FakeAz()
    assert cl_setup.main(argv, az=az, out_dir=tmp_path) == 2
    out, err = capsys.readouterr()
    assert "ENCRYPTION_KEY" in out + err and "REDIS_PASSWORD" in out + err
    assert "SESSION_SECRET" not in out + err
    assert az.calls == []
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloud-locksmith.env"]


def test_create_flow_writes_config_and_never_prints_secrets(tmp_path, capsys):
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    out, err = capsys.readouterr()

    config = cl_setup.parse_env(config_path(tmp_path).read_text())
    assert cl_setup.missing_keys(config) == []
    assert config["MICROSOFT_TENANT"] == TENANT
    assert config["MICROSOFT_CLIENT_ID"] == APP_ID
    assert config["MICROSOFT_CLIENT_SECRET"] == CLIENT_SECRET
    assert config["MICROSOFT_CLIENT_SECRET_KEY_ID"] == "key-1"
    assert config["MICROSOFT_CLIENT_SECRET_EXPIRES"] == "2028-11-18T10:00:00+00:00"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloud-locksmith-db.env", "cloud-locksmith.env"]
    assert cl_setup.parse_env(db_path(tmp_path).read_text()) == cl_setup.db_env(config)
    if os.name == "posix":
        assert stat.S_IMODE(db_path(tmp_path).stat().st_mode) == 0o600

    secret_keys = ("MICROSOFT_CLIENT_SECRET", "SESSION_SECRET", "APP_JWT_SECRET", "REPORT_SIGNING_SECRET")
    secret_keys += ("ENCRYPTION_KEY", "POSTGRES_PASSWORD", "REDIS_PASSWORD")
    for key in secret_keys:
        assert config[key] not in out + err, key
    assert "docker compose up -d" in out
    assert "http://localhost:3000" in out
    assert "Preview" in out
    assert "ssh -L" in out

    assert az.calls[0] == (["login", "--use-device-code", "--allow-no-subscriptions"], False)
    assert all(capture for _, capture in az.calls[1:])
    create = next(args for args, _ in az.calls if args[:3] == ["ad", "app", "create"])
    assert create[create.index("--display-name") + 1] == "Cloud Locksmith (local)"
    assert create[create.index("--sign-in-audience") + 1] == "AzureADMyOrg"
    assert create[create.index("--web-redirect-uris") + 1] == "http://localhost:8000/api/v1/auth/microsoft/callback"
    assert az.resource_access_file == [cl_setup.required_resource_access(DELEGATED_SCOPES, GRAPH_SCOPES)]
    reset = next(args for args, _ in az.calls if args[:4] == ["ad", "app", "credential", "reset"])
    assert reset[reset.index("--years") + 1] == "2" and "--append" in reset
    assert not any(args[0] == "rest" and "get" not in args for args, _ in az.calls)
    assert az.called("ad", "sp", "create", "--id", APP_ID)
    assert az.calls[-1] == (["logout"], True)
    assert not any("consent" in c or "role" in c for c in az.commands())
    assert not az.called("ad", "app", "delete")


def test_create_prints_the_signed_in_tenant_before_creating_the_app(tmp_path, capsys):
    az = FakeAz()
    printed = []

    def recording_az(args, capture=True):
        if args[:3] == ["ad", "app", "create"]:
            printed.append(capsys.readouterr().out)
        return az(args, capture)

    assert cl_setup.main([], az=recording_az, out_dir=tmp_path) == 0
    out = printed[0]
    assert f"Tenant: Contoso Ltd (contoso.com), tenant ID {TENANT}" in out
    # Only the name and the default domain come out of the organization object.
    rest = capsys.readouterr().out + out
    for other in ("contoso.onmicrosoft.com", "it@contoso.com", "Secret Street", "admin@example.com"):
        assert other not in rest


def test_tenant_line_falls_back_to_the_id_when_the_name_cannot_be_read(tmp_path, capsys):
    az = FakeAz()
    az.fail("rest", stderr="ERROR: Forbidden")
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    out = capsys.readouterr().out
    assert f"Tenant ID: {TENANT} (its name could not be read)" in out


def test_tenant_name_is_stripped_of_control_characters(tmp_path, capsys):
    az = FakeAz()
    az.organization["value"][0]["displayName"] = "Evil\x1b[2J\nCorp"
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "Tenant: Evil [2J Corp (contoso.com)" in out


@pytest.mark.parametrize("tenant", [TENANT, "contoso.onmicrosoft.com"])
def test_tenant_option_is_passed_to_sign_in(tmp_path, tenant):
    az = FakeAz()
    assert cl_setup.main(["--tenant", tenant], az=az, out_dir=tmp_path) == 0
    assert az.calls[0] == (
        ["login", "--use-device-code", "--allow-no-subscriptions", "--tenant", tenant],
        False,
    )


def test_tenant_option_is_passed_to_sign_in_for_rotate(tmp_path):
    az = FakeAz(creds=[{"keyId": "key-old", "endDateTime": "2027-01-01T00:00:00+00:00"}], secret=NEW_SECRET)
    write_both(tmp_path, complete_config())
    assert cl_setup.main(["--rotate-secret", "--tenant", TENANT], az=az, out_dir=tmp_path) == 0
    assert az.calls[0] == (
        ["login", "--use-device-code", "--allow-no-subscriptions", "--tenant", TENANT],
        False,
    )


@pytest.mark.parametrize("tenant", ["--use-device-code", "contoso", "a b.com", "", "x;y.com"])
def test_invalid_tenant_option_is_refused_before_sign_in(tmp_path, capsys, tenant):
    az = FakeAz()
    with pytest.raises(SystemExit) as exc:
        cl_setup.main(["--tenant", tenant], az=az, out_dir=tmp_path)
    assert exc.value.code == 2
    assert az.calls == []
    assert_nothing_written(tmp_path)


def test_signed_in_tenant_must_match_a_tenant_id_option(tmp_path, capsys):
    az = FakeAz(tenant="99999999-2222-4333-8444-555555555555")
    assert cl_setup.main(["--tenant", TENANT], az=az, out_dir=tmp_path) == 1
    assert not az.called("ad")
    assert TENANT in capsys.readouterr().err
    assert_nothing_written(tmp_path)


@pytest.mark.parametrize("failure", ["sp_create", "secret", "credential_list", "write", "main_write"])
def test_failure_after_app_create_deletes_app_and_writes_nothing(tmp_path, capsys, monkeypatch, failure):
    az = FakeAz()
    if failure == "sp_create":
        az.fail("ad", "sp", "create")
    elif failure == "secret":
        az.fail("ad", "app", "credential", "reset")
    elif failure == "credential_list":
        az.fail("ad", "app", "credential", "list")
    elif failure == "write":

        def broken_write(path, config):
            raise OSError("disk full")

        monkeypatch.setattr(cl_setup, "write_config", broken_write)
    else:
        real_write = cl_setup.write_config

        def main_write_fails(path, config):
            if path.name == "cloud-locksmith.env":
                raise OSError("disk full")
            real_write(path, config)

        monkeypatch.setattr(cl_setup, "write_config", main_write_fails)

    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    out, err = capsys.readouterr()
    assert az.called("ad", "app", "delete", "--id", APP_ID)
    assert az.called("logout")
    assert_nothing_written(tmp_path)
    assert CLIENT_SECRET not in out + err
    assert "deleted" in (out + err).lower()


def test_write_failure_removes_temp_file(tmp_path, monkeypatch):
    def broken_replace(src, dst):
        raise OSError("rename failed")

    monkeypatch.setattr(cl_setup.os, "replace", broken_replace)
    with pytest.raises(OSError):
        cl_setup.write_config(config_path(tmp_path), complete_config())
    assert_nothing_written(tmp_path)


def test_login_failure_writes_nothing(tmp_path, capsys):
    az = FakeAz()
    az.fail("login", stderr="az login exited with status 1")
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    out, err = capsys.readouterr()
    assert "sign-in" in (out + err).lower()
    assert [args[0] for args, _ in az.calls] == ["login"]
    assert_nothing_written(tmp_path)


def test_app_create_forbidden_gives_clear_message(tmp_path, capsys):
    az = FakeAz()
    az.fail(
        "ad",
        "app",
        "create",
        stderr="ERROR: Insufficient privileges to complete the operation. Authorization_RequestDenied",
    )
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    out, err = capsys.readouterr()
    assert "not allowed to register applications" in err
    assert "Nothing was created" in err
    assert not az.called("ad", "app", "delete")
    assert not az.called("ad", "app", "credential")
    assert az.called("logout")
    assert_nothing_written(tmp_path)


def test_existing_app_with_same_name_is_refused(tmp_path, capsys):
    az = FakeAz()
    az.existing_apps = [
        {"appId": "in-use-app-id", "displayName": "Cloud Locksmith (local)"},
        {"appId": "other-app-id", "displayName": "Cloud Locksmith (local) old"},
    ]
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    out, err = capsys.readouterr()
    assert "in-use-app-id" in err and "other-app-id" not in err
    assert "Nothing was created" in err
    lookup = next(args for args, _ in az.calls if args[:3] == ["ad", "app", "list"])
    assert lookup[lookup.index("--display-name") + 1] == "Cloud Locksmith (local)"
    assert not az.called("ad", "app", "create")
    assert not az.called("ad", "app", "delete")
    assert not az.called("ad", "app", "credential")
    assert az.called("logout")
    assert_nothing_written(tmp_path)


def test_app_with_only_a_longer_name_does_not_block_create(tmp_path):
    az = FakeAz()
    az.existing_apps = [{"appId": "other-app-id", "displayName": "Cloud Locksmith (local) old"}]
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 0
    assert az.called("ad", "app", "create")


def test_malformed_create_result_is_reported_and_writes_nothing(tmp_path, capsys):
    az = FakeAz()
    az.create_result = {"id": "object-id"}
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    err = capsys.readouterr().err
    assert "Cloud Locksmith (local)" in err and "Entra admin center" in err
    assert not az.called("ad", "sp", "create")
    assert az.called("logout")
    assert_nothing_written(tmp_path)


def test_personal_account_refused(tmp_path, capsys):
    az = FakeAz(tenant="9188040d-6c67-4c5b-b112-36a304b66dad")
    assert cl_setup.main([], az=az, out_dir=tmp_path) == 1
    out, err = capsys.readouterr()
    assert "personal Microsoft account" in err
    assert not az.called("ad")
    assert az.called("logout")
    assert_nothing_written(tmp_path)


def test_missing_out_dir_fails_before_sign_in(tmp_path, capsys):
    az = FakeAz()
    assert cl_setup.main([], az=az, out_dir=tmp_path / "absent") == 1
    assert az.calls == []
    assert "docker compose run --rm setup" in capsys.readouterr().err


def test_required_resource_access_covers_delegated_scopes():
    rra = cl_setup.required_resource_access(DELEGATED_SCOPES, GRAPH_SCOPES)
    assert rra["resourceAppId"] == "00000003-0000-0000-c000-000000000000"
    assert rra["resourceAccess"] == [{"id": f"scope-id-{name}", "type": "Scope"} for name in DELEGATED_SCOPES]
    assert cl_setup.DELEGATED_SCOPES is DELEGATED_SCOPES or cl_setup.DELEGATED_SCOPES == DELEGATED_SCOPES


def test_required_resource_access_missing_scope_raises():
    scopes = [s for s in GRAPH_SCOPES if s["value"] not in ("Policy.Read.All", "AuditLog.Read.All")]
    with pytest.raises(ValueError, match="Policy.Read.All") as excinfo:
        cl_setup.required_resource_access(DELEGATED_SCOPES, scopes)
    assert "AuditLog.Read.All" in str(excinfo.value)


def rotated(tmp_path, az):
    config = complete_config()
    path = config_path(tmp_path)
    cl_setup.write_config(path, config)
    before = path.read_bytes()
    code = cl_setup.main(["--rotate-secret"], az=az, out_dir=tmp_path)
    return code, config, before, path.read_bytes()


def test_rotate_replaces_only_secret_keys(tmp_path, capsys):
    az = FakeAz(creds=[{"keyId": "key-old", "endDateTime": "2027-01-01T00:00:00+00:00"}], secret=NEW_SECRET)
    code, old, before, after = rotated(tmp_path, az)
    assert code == 0
    out, err = capsys.readouterr()

    before_lines = before.split(b"\n")
    after_lines = after.split(b"\n")
    assert len(before_lines) == len(after_lines)
    changed = [b for b, a in zip(before_lines, after_lines) if b != a]
    assert sorted(line.split(b"=", 1)[0].decode() for line in changed) == sorted(SECRET_KEYS)

    new = cl_setup.parse_env(after.decode())
    assert new["MICROSOFT_CLIENT_SECRET"] == NEW_SECRET
    assert new["MICROSOFT_CLIENT_SECRET_KEY_ID"] == "key-2"
    assert new["MICROSOFT_CLIENT_SECRET_EXPIRES"] == "2028-11-18T10:00:00+00:00"
    assert az.called("ad", "app", "credential", "delete", "--id", APP_ID, "--key-id", "key-old")
    assert [c["keyId"] for c in az.creds] == ["key-2"]
    assert NEW_SECRET not in out + err and CLIENT_SECRET not in out + err
    assert az.called("logout")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloud-locksmith.env"]


def test_rotate_keeps_new_secret_when_old_delete_fails(tmp_path, capsys):
    az = FakeAz(creds=[{"keyId": "key-old", "endDateTime": "2027-01-01T00:00:00+00:00"}], secret=NEW_SECRET)
    az.fail("ad", "app", "credential", "delete", stderr="ERROR: Forbidden")
    code, old, before, after = rotated(tmp_path, az)
    assert code == 1
    out, err = capsys.readouterr()
    new = cl_setup.parse_env(after.decode())
    assert new["MICROSOFT_CLIENT_SECRET"] == NEW_SECRET
    assert new["MICROSOFT_CLIENT_SECRET_KEY_ID"] == "key-2"
    assert "key-old" in err
    assert NEW_SECRET not in out + err


def test_rotate_refuses_other_tenant(tmp_path, capsys):
    az = FakeAz(tenant="99999999-2222-4333-8444-555555555555", creds=[{"keyId": "key-old", "endDateTime": "x"}])
    code, old, before, after = rotated(tmp_path, az)
    assert code == 1
    assert after == before
    assert not az.called("ad")
    assert TENANT in capsys.readouterr().err


def test_rotate_without_config_fails(tmp_path, capsys):
    az = FakeAz()
    assert cl_setup.main(["--rotate-secret"], az=az, out_dir=tmp_path) == 1
    assert az.calls == []
    assert_nothing_written(tmp_path)


def test_az_error_redacts_secret_values(monkeypatch, capsys):
    stderr = (
        'ERROR: bad request {"password": "p4ss~w.rd", "clientSecret": "c1ient=sec-ret"} '
        "secret=plain.value-1 --password flagval~2"
    )

    def fake_run(cmd, **kwargs):
        assert cmd[0] == "az" and cmd[-2:] == ["-o", "json"]
        assert kwargs.get("capture_output") is True
        return subprocess.CompletedProcess(cmd, 1, stdout='{"password": "from-stdout"}', stderr=stderr)

    monkeypatch.setattr(cl_setup.subprocess, "run", fake_run)
    with pytest.raises(cl_setup.AzError) as excinfo:
        cl_setup.run_az(["ad", "app", "credential", "reset", "--id", APP_ID])
    message = str(excinfo.value)
    for value in ("p4ss~w.rd", "c1ient=sec-ret", "plain.value-1", "flagval~2", "from-stdout"):
        assert value not in message
    assert "bad request" in message
    out, err = capsys.readouterr()
    assert out == "" and err == ""


def test_run_az_returns_parsed_json_without_printing(monkeypatch, capsys):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout='{"password": "s"}', stderr="WARNING: protect it")

    monkeypatch.setattr(cl_setup.subprocess, "run", fake_run)
    assert cl_setup.run_az(["ad", "app", "credential", "reset"]) == {"password": "s"}
    assert capsys.readouterr() == ("", "")


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cl_setup.main(["--help"])
    assert excinfo.value.code == 0
    assert "--rotate-secret" in capsys.readouterr().out
