"""Unit tests for avi-controlscript-se-antiaffinitygroup.py.

No Avi controller or vCenter is needed: the Avi API session and vCenter
connection are replaced with fakes, and encryption uses throwaway keys from
conftest.py.
"""

# Test names describe each test; pytest fixtures are passed as arguments with
# the same names as the fixtures, and some tests need several of them.
# pylint: disable=missing-function-docstring,redefined-outer-name
# pylint: disable=too-many-arguments,too-many-positional-arguments

import json
import logging
import runpy
import sys
import warnings
from types import SimpleNamespace
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from pyVmomi import vim
from urllib3.exceptions import InsecureRequestWarning

from conftest import (
    SCRIPT_PATH,
    FakeAviSession,
    FakeContent,
    FakeResponse,
    FakeVM,
)

EVENT = {
    "events": [
        {"event_id": "SOMETHING_ELSE", "event_details": {}},
        {
            "event_id": "CREATED_SE",
            "obj_uuid": "serviceenginegroup-seg-1",
            "event_details": {
                "spawn_se_details": {
                    "se_name": "slb-se-eyiec",
                    "se_grp_name": "Default-Group",
                    "cloud_name": "Default-Cloud",
                }
            },
        },
    ]
}

RULE = "avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in (
        "FILEOBJECT_DOWNLOAD_PATH",
        "AVI_CREDENTIALS_CERT",
        "API_TOKEN",
        "USER",
        "TENANT",
        "DOCKER_GATEWAY",
    ):
        monkeypatch.delenv(var, raising=False)


def avi_cert_object(key_pem, cert_pem, passphrase=None):
    obj = {
        "key": key_pem.decode(),
        "certificate": {"certificate": cert_pem.decode()},
    }
    if passphrase:
        obj["key_passphrase"] = passphrase
    return obj


# ---------------------------------------------------------------------------
# parse_event
# ---------------------------------------------------------------------------


def test_parse_event_finds_created_se_event(cs):
    assert cs.parse_event(EVENT) == (
        "slb-se-eyiec",
        "Default-Group",
        "Default-Cloud",
        "serviceenginegroup-seg-1",
    )


def test_parse_event_without_cloud_name(cs):
    event = json.loads(json.dumps(EVENT))
    del event["events"][1]["event_details"]["spawn_se_details"]["cloud_name"]
    del event["events"][1]["obj_uuid"]
    assert cs.parse_event(event) == (
        "slb-se-eyiec",
        "Default-Group",
        None,
        None,
    )


def test_parse_event_ignores_obj_uuid_of_other_type(cs):
    """Only a serviceenginegroup UUID is taken as the SE group's."""
    event = json.loads(json.dumps(EVENT))
    event["events"][1]["obj_uuid"] = "se-1234"
    assert cs.parse_event(event)[3] is None


def test_parse_event_reads_sample_event_file(cs):
    with open(SCRIPT_PATH.parent / "event_data.json", encoding="utf-8") as f:
        assert cs.parse_event(json.load(f)) == (
            "slb-se-eyiec",
            "Default-Group",
            "Default-Cloud",
            "serviceenginegroup-04ddb86d-cacd-423d-99e4-8b807e9e2775",
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "events": [
                {
                    "event_id": "OTHER",
                    "event_details": {"spawn_se_details": {"se_name": "a"}},
                }
            ]
        },
        {"events": [{"event_id": "CREATED_SE", "event_details": {}}]},
    ],
)
def test_parse_event_without_created_se_raises(cs, payload):
    with pytest.raises(ValueError, match="No CREATED_SE event"):
        cs.parse_event(payload)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


def test_parse_args_takes_event_json_from_first_argument(cs):
    args = cs.parse_args([json.dumps(EVENT), "--dry-run", "--insecure"])
    assert args.event == EVENT
    assert args.dry_run and args.insecure


def test_parse_args_reads_event_file(cs, tmp_path):
    path = tmp_path / "event.json"
    path.write_text(json.dumps(EVENT))
    assert cs.parse_args(["--event-file", str(path)]).event == EVENT


def test_parse_args_defaults(cs):
    args = cs.parse_args([])
    assert args.event is None
    assert args.fileobject_download_path == "vcentercredentials.json.enc"
    assert args.credentials_cert == "controlscript-cert"
    assert not args.dry_run and not args.insecure


def test_parse_args_reads_environment(cs, monkeypatch):
    monkeypatch.setenv("FILEOBJECT_DOWNLOAD_PATH", "from-env")
    monkeypatch.setenv("AVI_CREDENTIALS_CERT", "env-cert")
    args = cs.parse_args([])
    assert args.fileobject_download_path == "from-env"
    assert args.credentials_cert == "env-cert"


def test_parse_args_cli_overrides_environment(cs, monkeypatch):
    monkeypatch.setenv("FILEOBJECT_DOWNLOAD_PATH", "from-env")
    args = cs.parse_args(
        ["--fileobject-download-path", "from-cli", "-se", "vm", "-seg", "grp"]
    )
    assert args.fileobject_download_path == "from-cli"
    assert (args.se_vm_name, args.service_engine_group) == ("vm", "grp")


# ---------------------------------------------------------------------------
# get_avi_session
# ---------------------------------------------------------------------------


def test_get_avi_session_requires_controlscript_environment(cs, monkeypatch):
    monkeypatch.setenv("USER", "admin")
    with pytest.raises(RuntimeError, match="API_TOKEN/USER not set"):
        cs.get_avi_session()


def test_get_avi_session_requires_docker_gateway(cs, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "tok")
    monkeypatch.setenv("USER", "script-user")
    with mock.patch("avi.sdk.avi_api.ApiSession.get_session") as get_session:
        with pytest.raises(RuntimeError, match="DOCKER_GATEWAY not set"):
            cs.get_avi_session()
    get_session.assert_not_called()


@pytest.mark.parametrize(
    "tenant, expected", [(None, "admin"), ("other", "other")]
)
def test_get_avi_session_uses_token(cs, monkeypatch, tenant, expected):
    monkeypatch.setenv("API_TOKEN", "tok")
    monkeypatch.setenv("USER", "script-user")
    monkeypatch.setenv("DOCKER_GATEWAY", "172.17.0.1")
    if tenant:
        monkeypatch.setenv("TENANT", tenant)
    with mock.patch(
        "avi.sdk.avi_api.ApiSession.get_session", return_value="session"
    ) as get_session:
        assert cs.get_avi_session() == "session"
    get_session.assert_called_once_with(
        "172.17.0.1",
        "script-user",
        # Fake test value.
        token="tok",  # nosec B106
        tenant=expected,
    )


# ---------------------------------------------------------------------------
# get_fileobject_contents
# ---------------------------------------------------------------------------


def test_get_fileobject_contents_looks_up_uuid_then_downloads(cs):
    session = FakeAviSession(
        objects={("fileobject", "vcenter-creds"): {"uuid": "fileobject-1"}},
        download=FakeResponse(b"encrypted-bytes"),
    )
    assert (
        cs.get_fileobject_contents(session, "vcenter-creds")
        == b"encrypted-bytes"
    )
    assert session.calls == [
        ("get_object_by_name", "fileobject", "vcenter-creds", None),
        ("get", "fileobject/fileobject-1/download", None),
    ]


def test_get_fileobject_contents_missing_fileobject(cs):
    with pytest.raises(
        RuntimeError,
        match="Fileobject 'vcentercredentials.json.enc' not found",
    ):
        cs.get_fileobject_contents(
            FakeAviSession(), "vcentercredentials.json.enc"
        )


def test_get_fileobject_contents_download_error(cs):
    session = FakeAviSession(
        objects={
            ("fileobject", "vcentercredentials.json.enc"): {
                "uuid": "fileobject-1"
            }
        },
        download=FakeResponse(b"forbidden", status_code=403),
    )
    with pytest.raises(RuntimeError, match="HTTP 403 forbidden"):
        cs.get_fileobject_contents(session, "vcentercredentials.json.enc")


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            json.dumps("file contents").encode(),
            b"file contents",
        ),  # JSON string: unwrapped
        (
            b'{"not": "a string"}',
            b'{"not": "a string"}',
        ),  # JSON, but not a string: as is
        (
            b"not json at all",
            b"not json at all",
        ),  # labelled JSON, isn't: as is
    ],
)
def test_get_fileobject_contents_json_responses(cs, body, expected):
    session = FakeAviSession(
        objects={
            ("fileobject", "vcentercredentials.json.enc"): {
                "uuid": "fileobject-1"
            }
        },
        download=FakeResponse(
            body, content_type="application/json; charset=utf-8"
        ),
    )
    assert (
        cs.get_fileobject_contents(session, "vcentercredentials.json.enc")
        == expected
    )


# ---------------------------------------------------------------------------
# get_key_and_cert
# ---------------------------------------------------------------------------


def test_get_key_and_cert_exports_key(cs, key_and_cert, key_pem, cert_pem):
    session = FakeAviSession(
        objects={
            ("sslkeyandcertificate", "cs-cert"): avi_cert_object(
                key_pem, cert_pem
            )
        }
    )
    key, cert = cs.get_key_and_cert(session, "cs-cert")
    assert key.private_numbers() == key_and_cert[0].private_numbers()
    assert cert == key_and_cert[1]
    assert session.calls == [
        (
            "get_object_by_name",
            "sslkeyandcertificate",
            "cs-cert",
            {"export_key": True},
        )
    ]


def test_get_key_and_cert_with_passphrase(cs, key_and_cert, cert_pem):
    encrypted_key_pem = key_and_cert[0].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"s3cret"),
    )
    obj = avi_cert_object(
        encrypted_key_pem,
        cert_pem,
        # Fake test value.
        passphrase="s3cret",  # nosec B106
    )
    key, _ = cs.get_key_and_cert(
        FakeAviSession(objects={("sslkeyandcertificate", "c"): obj}), "c"
    )
    assert key.private_numbers() == key_and_cert[0].private_numbers()


def test_get_key_and_cert_missing_certificate(cs):
    with pytest.raises(RuntimeError, match="Certificate 'nope' not found"):
        cs.get_key_and_cert(FakeAviSession(), "nope")


@pytest.mark.parametrize("key_value", [None, "", "<sensitive>"])
def test_get_key_and_cert_key_not_returned(cs, cert_pem, key_value):
    obj = {"certificate": {"certificate": cert_pem.decode()}}
    if key_value is not None:
        obj["key"] = key_value
    with pytest.raises(RuntimeError, match="didn't return the private key"):
        cs.get_key_and_cert(
            FakeAviSession(objects={("sslkeyandcertificate", "c"): obj}), "c"
        )


# ---------------------------------------------------------------------------
# parse_vcenter_credentials
# ---------------------------------------------------------------------------


def test_parse_vcenter_credentials_plain_local_file(cs, tmp_path, creds_bytes):
    path = tmp_path / "credentials.json"
    path.write_bytes(creds_bytes)
    args = cs.parse_args(["--credentials-file", str(path)])
    assert cs.parse_vcenter_credentials(args) == (
        "vc.example.test",
        "svc@vsphere.local",
        "test-password",
    )


def test_parse_vcenter_credentials_encrypted_local_file(
    cs, tmp_path, key_pem, cert_pem, encrypt, creds_bytes
):
    (tmp_path / "creds.enc").write_bytes(
        encrypt(creds_bytes, serialization.Encoding.SMIME)
    )
    (tmp_path / "key.pem").write_bytes(key_pem)
    (tmp_path / "cert.pem").write_bytes(cert_pem)
    args = cs.parse_args(
        [
            "--credentials-file",
            str(tmp_path / "creds.enc"),
            "--key-file",
            str(tmp_path / "key.pem"),
            "--cert-file",
            str(tmp_path / "cert.pem"),
        ]
    )
    assert cs.parse_vcenter_credentials(args) == (
        "vc.example.test",
        "svc@vsphere.local",
        "test-password",
    )


def test_parse_vcenter_credentials_key_file_needs_cert_file(
    cs, tmp_path, creds_bytes
):
    (tmp_path / "creds.enc").write_bytes(creds_bytes)
    args = cs.parse_args(
        [
            "--credentials-file",
            str(tmp_path / "creds.enc"),
            "--key-file",
            "key.pem",
        ]
    )
    with pytest.raises(RuntimeError, match="--key-file needs --cert-file"):
        cs.parse_vcenter_credentials(args)


def test_parse_vcenter_credentials_controller_needs_cert_name(cs):
    with pytest.raises(RuntimeError, match="Set --credentials-cert"):
        cs.parse_vcenter_credentials(cs.parse_args(["--credentials-cert", ""]))


def test_parse_vcenter_credentials_from_controller(
    cs, monkeypatch, key_pem, cert_pem, encrypt, creds_bytes
):
    session = FakeAviSession(
        objects={
            ("sslkeyandcertificate", "cs-cert"): avi_cert_object(
                key_pem, cert_pem
            ),
            ("fileobject", "vcenter-creds"): {"uuid": "fileobject-9"},
        },
        download=FakeResponse(
            encrypt(creds_bytes, serialization.Encoding.SMIME)
        ),
    )
    monkeypatch.setattr(cs, "get_avi_session", lambda: session)
    args = cs.parse_args(
        [
            "--credentials-cert",
            "cs-cert",
            "--fileobject-download-path",
            "vcenter-creds",
        ]
    )
    assert cs.parse_vcenter_credentials(args) == (
        "vc.example.test",
        "svc@vsphere.local",
        "test-password",
    )
    assert ("get", "fileobject/fileobject-9/download", None) in session.calls


def test_parse_vcenter_credentials_default_fileobject_name(
    cs, monkeypatch, key_pem, cert_pem, encrypt, creds_bytes
):
    """With no override, the fileobject is DEFAULT_CREDENTIALS_FILENAME."""
    session = FakeAviSession(
        objects={
            ("sslkeyandcertificate", "controlscript-cert"): avi_cert_object(
                key_pem, cert_pem
            ),
            ("fileobject", cs.DEFAULT_CREDENTIALS_FILENAME): {
                "uuid": "fileobject-3"
            },
        },
        download=FakeResponse(
            encrypt(creds_bytes, serialization.Encoding.SMIME)
        ),
    )
    monkeypatch.setattr(cs, "get_avi_session", lambda: session)
    assert cs.parse_vcenter_credentials(cs.parse_args([]))[0] == (
        "vc.example.test"
    )
    assert (
        "get_object_by_name",
        "fileobject",
        "vcentercredentials.json.enc",
        None,
    ) in session.calls


# ---------------------------------------------------------------------------
# find_vm / get_cluster / get_controller_cluster_name
# ---------------------------------------------------------------------------


def test_find_vm_returns_match(cs):
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    content = FakeContent([FakeVM("vm-2", "other"), vm])
    assert cs.find_vm(content, "slb-se-aaaaa") is vm
    assert content.views[0].destroyed


def test_find_vm_returns_none_when_missing(cs):
    assert (
        cs.find_vm(FakeContent([FakeVM("vm-2", "other")]), "slb-se-aaaaa")
        is None
    )


def test_find_vm_rejects_duplicate_names(cs):
    content = FakeContent([FakeVM("vm-1", "dup"), FakeVM("vm-2", "dup")])
    with pytest.raises(RuntimeError, match="More than one VM named 'dup'"):
        cs.find_vm(content, "dup")
    assert content.views[0].destroyed


def test_get_cluster_returns_hosts_cluster(cs):
    cluster = vim.ClusterComputeResource("domain-c1")
    vm = FakeVM("vm-1", "se", host=SimpleNamespace(parent=cluster))
    assert cs.get_cluster(vm) is cluster


@pytest.mark.parametrize("host", [None, SimpleNamespace(parent=object())])
def test_get_cluster_requires_cluster(cs, host):
    with pytest.raises(
        RuntimeError, match="not running on a host in a cluster"
    ):
        cs.get_cluster(FakeVM("vm-1", "se", host=host))


def test_get_controller_cluster_name(cs):
    session = FakeAviSession(
        responses={
            "cluster": FakeResponse(
                json.dumps({"name": "avi.example.com", "uuid": "c-1"}).encode()
            )
        }
    )
    assert cs.get_controller_cluster_name(session) == "avi.example.com"
    assert session.calls == [("get", "cluster", None)]


@pytest.mark.parametrize(
    "response, message",
    [
        (FakeResponse(b"denied", status_code=403), "HTTP 403 denied"),
        (FakeResponse(b'{"uuid": "c-1"}'), "cluster has no name"),
    ],
    ids=["http-error", "no-name"],
)
def test_get_controller_cluster_name_errors(cs, response, message):
    session = FakeAviSession(responses={"cluster": response})
    with pytest.raises(RuntimeError, match=message):
        cs.get_controller_cluster_name(session)


# ---------------------------------------------------------------------------
# quiet_ssl_warnings
# ---------------------------------------------------------------------------

# The warning the Avi SDK gives for every session made with verify=False.
AVI_SDK_WARNING = (
    "\n"
    + "*" * 80
    + "\nStrong Recommendation: It is highly recommended to use verify=True \n"
    "to enable SSL certificate validation and ensure secure communication.\n"
    + "*" * 80
)


@pytest.fixture
def quiet(cs):
    """Call quiet_ssl_warnings, and undo its change to the SDK's logger."""
    sdk_logger = logging.getLogger("avi.sdk.avi_api")
    before = list(sdk_logger.filters)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cs.quiet_ssl_warnings()
        yield caught
    sdk_logger.filters[:] = before


def test_quiet_ssl_warnings_hides_sdk_and_urllib3_warnings(quiet):
    warnings.warn(AVI_SDK_WARNING)
    warnings.warn("Unverified HTTPS request", InsecureRequestWarning)
    warnings.warn("something else")
    assert [str(w.message) for w in quiet] == ["something else"]


@pytest.mark.usefixtures("quiet")
def test_quiet_ssl_warnings_hides_sdk_log_message(caplog):
    sdk_logger = logging.getLogger("avi.sdk.avi_api")
    with caplog.at_level("WARNING"):
        sdk_logger.warning(AVI_SDK_WARNING)
        sdk_logger.warning("Warning: Object Not found for fileobject")
    assert [r.getMessage() for r in caplog.records] == [
        "Warning: Object Not found for fileobject"
    ]


def test_main_quiets_ssl_warnings(cs, monkeypatch):
    quiet_mock = mock.Mock()
    monkeypatch.setattr(cs, "quiet_ssl_warnings", quiet_mock)
    assert cs.main([]) == 2
    quiet_mock.assert_called_once_with()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


@pytest.fixture
def vcenter(cs, monkeypatch):
    """Patch credentials and the vCenter connection.

    Returns the mocks for inspection.
    """
    vm = FakeVM(
        "vm-1",
        "slb-se-eyiec",
        host=SimpleNamespace(parent=vim.ClusterComputeResource("domain-c1")),
    )
    content = FakeContent([vm])
    si = mock.Mock(RetrieveContent=mock.Mock(return_value=content))
    mocks = SimpleNamespace(
        vm=vm,
        si=si,
        connect=mock.Mock(return_value=si),
        disconnect=mock.Mock(),
        add=mock.Mock(),
        creds=mock.Mock(return_value=("vc.example.test", "user", "pw")),
        avi_session=mock.Mock(),
        se_names=mock.Mock(return_value=["slb-se-eyiec", "slb-se-other"]),
        controller=mock.Mock(return_value="avi.example.com"),
    )
    monkeypatch.setattr(cs, "SmartConnect", mocks.connect)
    monkeypatch.setattr(cs, "Disconnect", mocks.disconnect)
    monkeypatch.setattr(cs, "add_vm_to_anti_affinity_rule", mocks.add)
    monkeypatch.setattr(cs, "parse_vcenter_credentials", mocks.creds)
    monkeypatch.setattr(cs, "get_avi_session", mocks.avi_session)
    monkeypatch.setattr(cs, "get_se_group_se_names", mocks.se_names)
    monkeypatch.setattr(cs, "get_controller_cluster_name", mocks.controller)
    return mocks


def test_main_updates_rule_for_event(cs, vcenter):
    assert cs.main([json.dumps(EVENT), "--insecure", "--dry-run"]) == 0
    vcenter.connect.assert_called_once_with(
        host="vc.example.test",
        user="user",
        # Fake test value.
        pwd="pw",  # nosec B106
        disableSslCertValidation=True,
    )
    content, cluster, vm, rule_name, se_names = vcenter.add.call_args.args
    assert content is vcenter.si.RetrieveContent.return_value
    assert vm is vcenter.vm and rule_name == RULE
    vcenter.controller.assert_called_once_with(
        vcenter.avi_session.return_value
    )
    vcenter.se_names.assert_called_once_with(
        vcenter.avi_session.return_value,
        "Default-Group",
        "Default-Cloud",
        "serviceenginegroup-seg-1",
    )
    assert se_names == ["slb-se-eyiec", "slb-se-other"]
    assert isinstance(cluster, vim.ClusterComputeResource)
    assert vcenter.add.call_args.kwargs == {"dry_run": True}
    vcenter.disconnect.assert_called_once_with(vcenter.si)


def test_main_skips_vcenter_cert_validation_by_default(cs, vcenter):
    assert cs.VERIFY_VCENTER_CERT is False
    assert cs.main([json.dumps(EVENT)]) == 0
    assert vcenter.connect.call_args.kwargs["disableSslCertValidation"] is True


@pytest.mark.parametrize(
    "extra_args, disabled", [([], False), (["--insecure"], True)]
)
def test_main_verify_vcenter_cert_setting(
    cs, vcenter, monkeypatch, extra_args, disabled
):
    """With VERIFY_VCENTER_CERT on, --insecure still turns it off."""
    monkeypatch.setattr(cs, "VERIFY_VCENTER_CERT", True)
    assert cs.main([json.dumps(EVENT), *extra_args]) == 0
    assert (
        vcenter.connect.call_args.kwargs["disableSslCertValidation"]
        is disabled
    )


def test_main_overrides_from_cli(cs, vcenter):
    vcenter.vm.__dict__["_fake_name"] = "other-se-zzzzz"
    argv = [json.dumps(EVENT), "-se", "other-se-zzzzz", "-seg", "Group2"]
    assert cs.main(argv + ["--cloud-name", "Cloud2"]) == 0
    assert vcenter.add.call_args.args[3] == (
        "avi_se_antiaffinity_avi.example.com_Cloud2_Group2"
    )
    assert vcenter.se_names.call_args.args[1:] == ("Group2", "Cloud2", None)


@pytest.mark.parametrize(
    "override, expected",
    [
        (["-seg", "Group2"], ("Group2", "Default-Cloud", None)),
        (["--cloud-name", "Cloud2"], ("Default-Group", "Cloud2", None)),
    ],
)
def test_main_override_drops_alert_se_group_uuid(
    cs, vcenter, override, expected
):
    """The alert's SE group UUID isn't used for another group or cloud."""
    assert cs.main([json.dumps(EVENT), *override]) == 0
    assert vcenter.se_names.call_args.args[1:] == expected


def test_main_local_testing_options_skip_avi_api(cs, vcenter):
    """--se-group-members and --controller-fqdn replace the Avi API."""
    argv = [json.dumps(EVENT), "--se-group-members", "slb-se-eyiec", "se-2"]
    assert cs.main(argv + ["--controller-fqdn", "ctl.example.net"]) == 0
    vcenter.avi_session.assert_not_called()
    vcenter.se_names.assert_not_called()
    vcenter.controller.assert_not_called()
    assert vcenter.add.call_args.args[3] == (
        "avi_se_antiaffinity_ctl.example.net_Default-Cloud_Default-Group"
    )
    assert vcenter.add.call_args.args[4] == ["slb-se-eyiec", "se-2"]


def test_main_without_event_or_names(cs, vcenter):
    assert cs.main([]) == 2
    vcenter.connect.assert_not_called()


def test_main_without_cloud_name(cs, vcenter, caplog):
    """No cloud name in the event or on the command line: exit status 2."""
    assert cs.main(["-se", "slb-se-eyiec", "-seg", "Default-Group"]) == 2
    assert "No SE name/SE group/cloud name" in caplog.text
    vcenter.connect.assert_not_called()


def test_main_vm_not_in_vcenter(cs, vcenter):
    argv = ["-se", "missing-se-xxxxx", "-seg", "Default-Group"]
    assert cs.main(argv + ["--cloud-name", "Default-Cloud"]) == 1
    vcenter.add.assert_not_called()
    vcenter.disconnect.assert_called_once_with(vcenter.si)


def test_main_disconnects_on_error(cs, vcenter):
    vcenter.add.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        cs.main([json.dumps(EVENT)])
    vcenter.disconnect.assert_called_once_with(vcenter.si)


def test_script_entry_point_exits_with_main_status(monkeypatch):
    """Running the file as a script calls main() and exits with its status.

    With no event given, main() returns 2.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
    assert exc.value.code == 2
