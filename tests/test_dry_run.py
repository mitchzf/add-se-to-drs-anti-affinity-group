"""The README's local --dry-run commands, with vCenter mocked.

Run by hand, those commands log in to the vCenter named in the credentials
file (--dry-run only skips the change). These tests run the same commands
through main(), with the repository's event_data.json and test credentials
encrypted to a throwaway key, but with SmartConnect replaced by a mock, so
nothing real is contacted.
"""

# pytest fixtures are passed as arguments with the same names as the
# fixtures.
# pylint: disable=missing-function-docstring,redefined-outer-name

import socket
from types import SimpleNamespace
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from pyVmomi import vim

from conftest import (
    CREDS,
    PROJECT_DIR,
    FakeCluster,
    FakeContent,
    FakeVM,
    NetworkBlockedError,
)

RULE = "avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group"
README_ARGS = [
    "--event-file",
    str(PROJECT_DIR / "event_data.json"),
    "--controller-fqdn",
    "avi.example.com",
    "--se-group-members",
    "slb-se-eyiec",
    "slb-se-abcde",
    "--dry-run",
]


@pytest.fixture
def fake_vcenter(cs, monkeypatch):
    """Replace vCenter with a mock holding both SE VMs in one cluster.

    The Avi API and WaitForTask fail the test if they're used: the
    command-line options replace the Avi API, and a dry run changes nothing.
    """
    cluster = FakeCluster("domain-c1")
    host = SimpleNamespace(parent=cluster)
    vms = [
        FakeVM("vm-1", "slb-se-eyiec", host=host),
        FakeVM("vm-2", "slb-se-abcde", host=host),
        FakeVM("vm-3", "web01", host=host),
    ]
    si = mock.Mock(
        RetrieveContent=mock.Mock(return_value=FakeContent(all_vms=vms))
    )
    fake = SimpleNamespace(
        cluster=cluster,
        vms=vms,
        si=si,
        connect=mock.Mock(return_value=si),
        disconnect=mock.Mock(),
    )
    monkeypatch.setattr(cs, "SmartConnect", fake.connect)
    monkeypatch.setattr(cs, "Disconnect", fake.disconnect)
    unexpected = mock.Mock(side_effect=AssertionError("unexpected call"))
    monkeypatch.setattr(cs, "WaitForTask", unexpected)
    monkeypatch.setattr(cs, "get_avi_session", unexpected)
    return fake


def assert_dry_run(fake, caplog, expected):
    """vCenter was 'connected' with the file's credentials; nothing changed."""
    fake.connect.assert_called_once_with(
        host=CREDS["vcenter"],
        user=CREDS["username"],
        pwd=CREDS["password"],
        disableSslCertValidation=True,
    )
    fake.disconnect.assert_called_once_with(fake.si)
    assert not fake.cluster.reconfigure_calls
    assert f"[dry run] {expected} on cluster 'cl1'" in caplog.text


def test_dry_run_plain_credentials_file(
    cs, fake_vcenter, tmp_path, creds_bytes, caplog
):
    """README: plain-text credentials file."""
    creds = tmp_path / "credentials.json"
    creds.write_bytes(creds_bytes)

    with caplog.at_level("INFO"):
        assert cs.main(README_ARGS + ["--credentials-file", str(creds)]) == 0

    assert_dry_run(
        fake_vcenter,
        caplog,
        f"Creating rule '{RULE}' with slb-se-abcde, slb-se-eyiec",
    )


@pytest.fixture(
    params=[
        serialization.Encoding.SMIME,
        serialization.Encoding.PEM,
        serialization.Encoding.DER,
    ],
    ids=["smime", "pem", "der"],
)
# pytest passes each fixture this one needs as its own argument.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def encrypted_files(
    request, tmp_path, creds_bytes, encrypt, key_pem, cert_pem
):
    """Encrypted credentials file, key and certificate, as README options."""
    files = {
        "--credentials-file": (
            "credentials.json.enc",
            encrypt(creds_bytes, request.param),
        ),
        "--key-file": ("key.pem", key_pem),
        "--cert-file": ("cert.pem", cert_pem),
    }
    argv = []
    for option, (name, data) in files.items():
        (tmp_path / name).write_bytes(data)
        argv += [option, str(tmp_path / name)]
    return argv


def test_dry_run_encrypted_credentials_file(
    cs, fake_vcenter, encrypted_files, caplog
):
    """README: encrypted file, with a local copy of the key and cert."""
    with caplog.at_level("INFO"):
        assert cs.main(README_ARGS + encrypted_files) == 0

    assert_dry_run(
        fake_vcenter,
        caplog,
        f"Creating rule '{RULE}' with slb-se-abcde, slb-se-eyiec",
    )


def test_dry_run_existing_rule(
    cs, fake_vcenter, tmp_path, creds_bytes, caplog
):
    """With the rule in vCenter, the dry run reports the VMs it would add."""
    fake_vcenter.cluster.configurationEx.rule.append(
        vim.cluster.AntiAffinityRuleSpec(
            key=7, name=RULE, enabled=True, vm=[fake_vcenter.vms[1]]
        )
    )
    creds = tmp_path / "credentials.json"
    creds.write_bytes(creds_bytes)

    with caplog.at_level("INFO"):
        assert cs.main(README_ARGS + ["--credentials-file", str(creds)]) == 0

    assert_dry_run(
        fake_vcenter,
        caplog,
        f"Adding slb-se-eyiec to existing rule '{RULE}'",
    )


def test_real_smartconnect_is_blocked(cs, tmp_path, creds_bytes):
    """Without the vCenter mock, the test fails instead of connecting."""
    creds = tmp_path / "credentials.json"
    creds.write_bytes(creds_bytes)
    with pytest.raises(NetworkBlockedError):
        cs.main(README_ARGS + ["--credentials-file", str(creds)])


def test_network_is_blocked():
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("vc.example.test", 443))
