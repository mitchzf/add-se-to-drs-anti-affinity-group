"""Tests for finding the SE group's SEs and putting them in the DRS rule."""

# pytest fixtures are passed as arguments with the same names as the
# fixtures.
# pylint: disable=missing-function-docstring,redefined-outer-name

from types import SimpleNamespace
from unittest import mock

import pytest
from pyVmomi import vim

from conftest import FakeAviSession, FakeCluster, FakeContent, FakeVM

SEG_REF = "https://10.0.0.1/api/serviceenginegroup/serviceenginegroup-seg-1"
AVI_SES = [
    {"name": "slb-se-aaaaa", "se_group_ref": SEG_REF},
    {"name": "slb-se-other", "se_group_ref": SEG_REF + "x"},
    {"name": "slb-se-nogroup"},
    {"name": "slb-se-bb", "se_group_ref": SEG_REF + "#Default-Group"},
]


def test_get_se_group_se_names_by_alert_uuid(cs, caplog):
    """With the alert's SE group UUID, SEs are filtered by se_group_ref."""
    session = FakeAviSession(lists={"serviceengine": AVI_SES})
    with caplog.at_level("INFO"):
        names = cs.get_se_group_se_names(
            session,
            "Default-Group",
            "Default-Cloud",
            "serviceenginegroup-seg-1",
        )
    assert names == ["slb-se-aaaaa", "slb-se-bb"]
    assert session.calls == [
        (
            "get_objects_iter",
            "serviceengine",
            {"fields": "name,se_group_ref"},
        )
    ]
    assert "Avi API lists 2 SE(s) in SE group 'Default-Group'" in caplog.text


def test_get_se_group_se_names_by_name_in_cloud(cs):
    """Without a UUID, the SE group is looked up by name in its cloud."""
    session = FakeAviSession(
        objects={
            ("serviceenginegroup", "Default-Group"): {
                "uuid": "serviceenginegroup-seg-1"
            }
        },
        lists={"serviceengine": AVI_SES},
    )
    assert cs.get_se_group_se_names(
        session, "Default-Group", "Default-Cloud"
    ) == ["slb-se-aaaaa", "slb-se-bb"]
    assert session.calls[0] == (
        "get_object_by_name",
        "serviceenginegroup",
        "Default-Group",
        {"cloud_ref.name": "Default-Cloud"},
    )


def test_get_se_group_se_names_none_listed(cs, caplog):
    session = FakeAviSession(lists={"serviceengine": AVI_SES})
    with caplog.at_level("INFO"):
        assert not cs.get_se_group_se_names(session, "G", "C", "seg-none")
    assert "lists 0 SE(s) in SE group 'G' (seg-none): none" in caplog.text


def test_get_se_group_se_names_unknown_group(cs):
    with pytest.raises(
        RuntimeError, match="SE group 'nope' not found in cloud 'C'"
    ):
        cs.get_se_group_se_names(FakeAviSession(), "nope", "C")


@pytest.mark.parametrize(
    "ref, uuid",
    [
        (None, None),
        ("", None),
        ("https://h/api/serviceenginegroup/seg-1", "seg-1"),
        ("https://h/api/serviceenginegroup/seg-1#Default-Group", "seg-1"),
        ("seg-1", "seg-1"),
    ],
)
def test_ref_uuid(cs, ref, uuid):
    assert cs.ref_uuid(ref) == uuid


def in_cluster(cluster, vms):
    """Put the VMs on a host in the cluster; return content listing them."""
    for vm in vms:
        vm.runtime.host = SimpleNamespace(parent=cluster)
    return FakeContent(all_vms=vms)


def test_find_se_group_vms_uses_avi_se_names(cs, caplog):
    """The group's SEs by name, whatever the names look like, then the VM.

    SEs in another cluster or missing from vCenter are left out, with a
    warning.
    """
    cluster = FakeCluster("domain-c1")
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    sibling = FakeVM("vm-2", "renamed-vm")
    content = in_cluster(
        cluster,
        [
            vm,
            sibling,
            FakeVM("vm-3", "slb-se-ccccc"),  # same prefix, other group
            FakeVM("vm-4", "web01"),
        ],
    )
    away = FakeVM(
        "vm-5",
        "slb-se-away",
        host=SimpleNamespace(parent=FakeCluster("domain-c2", name="cl2")),
    )
    content.all_vms += [away, FakeVM("vm-6", "slb-se-nohost")]
    se_names = [
        "slb-se-aaaaa",
        "renamed-vm",
        "slb-se-elsewhere",
        "slb-se-away",
        "slb-se-nohost",
    ]
    with caplog.at_level("WARNING"):
        assert cs.find_se_group_vms(content, cluster, vm, se_names) == [
            sibling,
            vm,
        ]
    assert content.views[0].destroyed
    assert "'slb-se-away' is in cluster 'cl2', not 'cl1'" in caplog.text
    assert "'slb-se-nohost' is in cluster 'None'" in caplog.text
    assert "SE 'slb-se-elsewhere' (from the Avi API) has no VM" in caplog.text


# ---------------------------------------------------------------------------
# add_vm_to_anti_affinity_rule
# ---------------------------------------------------------------------------

RULE = "avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group"


def make_cluster(rules=()):
    cluster = mock.MagicMock()
    cluster.name = "cl1"
    cluster.configurationEx.rule = list(rules)
    return cluster


def reconfigure_spec(cluster):
    (spec,), kwargs = cluster.ReconfigureComputeResource_Task.call_args
    assert kwargs == {"modify": True}
    return spec.rulesSpec[0]


def test_add_vm_all_group_vms_already_in_rule(cs, monkeypatch, caplog):
    """Every group VM in the cluster is in the rule: nothing changes."""
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    sibling = FakeVM("vm-2", "slb-se-b")
    rule = vim.cluster.AntiAffinityRuleSpec(
        key=5, name=RULE, enabled=True, vm=[sibling, vm]
    )
    cluster = make_cluster([rule])
    monkeypatch.setattr(cs, "WaitForTask", mock.Mock())
    with caplog.at_level("INFO"):
        cs.add_vm_to_anti_affinity_rule(
            in_cluster(cluster, [vm, sibling]),
            cluster,
            vm,
            RULE,
            ["slb-se-aaaaa", "slb-se-b"],
        )
    cluster.ReconfigureComputeResource_Task.assert_not_called()
    assert "are already in rule" in caplog.text


def test_add_vm_in_rule_but_group_vm_missing(cs, monkeypatch):
    """The new VM is in the rule already, but another group VM isn't.

    Only the missing VM is added; nothing in the rule is added twice.
    """
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    sibling = FakeVM("vm-2", "slb-se-b")
    missed = FakeVM("vm-3", "slb-se-c")
    rule = vim.cluster.AntiAffinityRuleSpec(
        key=5, name=RULE, enabled=True, vm=[sibling, vm]
    )
    cluster = make_cluster([rule])
    monkeypatch.setattr(cs, "WaitForTask", mock.Mock())
    cs.add_vm_to_anti_affinity_rule(
        in_cluster(cluster, [vm, sibling, missed]),
        cluster,
        vm,
        RULE,
        ["slb-se-aaaaa", "slb-se-b", "slb-se-c"],
    )
    rule_spec = reconfigure_spec(cluster)
    assert rule_spec.operation == "edit" and rule_spec.info.key == 5
    assert list(rule_spec.info.vm) == [sibling, vm, missed]


def test_add_vm_adds_only_missing_group_vms(cs, monkeypatch, caplog):
    """The rule gets the group's missing VMs; its other VMs stay.

    vm-2 is already in the rule, vm-3 and the new VM aren't. vm-9 is in the
    rule but not the group (say, a deleted SE's VM name was reused): it's
    kept. web01 is in the cluster but not the group: it's left out.
    """
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    in_rule = FakeVM("vm-2", "slb-se-bbbbb")
    missed = FakeVM("vm-3", "slb-se-ccccc")
    stray = FakeVM("vm-9", "slb-se-old")
    rule = vim.cluster.AntiAffinityRuleSpec(
        key=7, name=RULE, enabled=True, vm=[in_rule, stray]
    )
    cluster = make_cluster([rule])
    monkeypatch.setattr(cs, "WaitForTask", mock.Mock())
    content = in_cluster(
        cluster, [in_rule, missed, FakeVM("vm-4", "web01"), vm, stray]
    )
    with caplog.at_level("INFO"):
        cs.add_vm_to_anti_affinity_rule(
            content,
            cluster,
            vm,
            RULE,
            ["slb-se-aaaaa", "slb-se-bbbbb", "slb-se-ccccc"],
        )
    rule_spec = reconfigure_spec(cluster)
    assert rule_spec.operation == "edit"
    assert list(rule_spec.info.vm) == [in_rule, stray, missed, vm]
    assert (
        f"Adding slb-se-ccccc, slb-se-aaaaa to existing rule '{RULE}'"
        in caplog.text
    )


def test_add_vm_to_existing_rule(cs, monkeypatch):
    existing_vms = [
        FakeVM("vm-2", "slb-se-bbbbb"),
        FakeVM("vm-3", "slb-se-ccccc"),
    ]
    rules = [
        vim.cluster.AffinityRuleSpec(
            name=RULE, vm=[FakeVM("vm-8", "x")]
        ),  # same name, wrong type: ignored
        vim.cluster.AntiAffinityRuleSpec(
            key=1, name="other-rule", vm=[FakeVM("vm-9", "y")]
        ),
        vim.cluster.AntiAffinityRuleSpec(
            key=7, name=RULE, enabled=False, vm=existing_vms
        ),
    ]
    cluster = make_cluster(rules)
    wait = mock.Mock()
    monkeypatch.setattr(cs, "WaitForTask", wait)
    vm = FakeVM("vm-1", "slb-se-aaaaa")

    cs.add_vm_to_anti_affinity_rule(
        FakeContent(), cluster, vm, RULE, [v.name for v in existing_vms]
    )

    rule_spec = reconfigure_spec(cluster)
    assert rule_spec.operation == "edit"
    assert (
        rule_spec.info.key == 7
        and rule_spec.info.name == RULE
        and rule_spec.info.enabled is False
    )
    assert list(rule_spec.info.vm) == existing_vms + [vm]
    wait.assert_called_once_with(
        cluster.ReconfigureComputeResource_Task.return_value
    )


def test_add_vm_creates_rule_with_all_group_vms(cs, monkeypatch):
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    sibling = FakeVM("vm-2", "slb-se-bbbbb")
    cluster = make_cluster()
    monkeypatch.setattr(cs, "WaitForTask", mock.Mock())

    cs.add_vm_to_anti_affinity_rule(
        in_cluster(cluster, [vm, FakeVM("vm-3", "web01"), sibling]),
        cluster,
        vm,
        RULE,
        ["slb-se-aaaaa", "slb-se-bbbbb"],
    )

    rule_spec = reconfigure_spec(cluster)
    assert rule_spec.operation == "add"
    assert (
        rule_spec.info.name == RULE
        and rule_spec.info.enabled
        and rule_spec.info.userCreated
    )
    assert list(rule_spec.info.vm) == [sibling, vm]


def test_add_vm_no_rule_and_no_siblings_in_cluster(cs, caplog):
    """The group has two SEs, but the other one is in another cluster."""
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    cluster = make_cluster()
    with caplog.at_level("INFO"):
        cs.add_vm_to_anti_affinity_rule(
            in_cluster(cluster, [vm]),
            cluster,
            vm,
            RULE,
            ["slb-se-aaaaa", "slb-se-bbbbb"],
        )
    cluster.ReconfigureComputeResource_Task.assert_not_called()
    assert "the rule will be created when the next SE is added" in caplog.text


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize("se_names", [[], ["slb-se-aaaaa"]])
def test_add_vm_needs_two_ses_in_group(cs, caplog, existing, se_names):
    """With one SE in the group, the rule isn't created or changed.

    The new SE counts whether or not Avi lists it yet.
    """
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    other = FakeVM("vm-2", "slb-se-bbbbb")  # in the cluster, not the group
    rules = (
        [
            vim.cluster.AntiAffinityRuleSpec(
                key=7, name=RULE, enabled=True, vm=[other]
            )
        ]
        if existing
        else []
    )
    cluster = make_cluster(rules)
    content = in_cluster(cluster, [vm, other])
    with caplog.at_level("INFO"):
        cs.add_vm_to_anti_affinity_rule(content, cluster, vm, RULE, se_names)
    cluster.ReconfigureComputeResource_Task.assert_not_called()
    assert "only SE in its SE group" in caplog.text
    assert not content.views


@pytest.mark.parametrize("existing", [True, False])
def test_add_vm_dry_run_changes_nothing(cs, caplog, existing):
    vm = FakeVM("vm-1", "slb-se-aaaaa")
    sibling = FakeVM("vm-2", "slb-se-bbbbb")
    rules = (
        [
            vim.cluster.AntiAffinityRuleSpec(
                key=7, name=RULE, enabled=True, vm=[sibling]
            )
        ]
        if existing
        else []
    )
    cluster = make_cluster(rules)
    with caplog.at_level("INFO"):
        cs.add_vm_to_anti_affinity_rule(
            in_cluster(cluster, [vm, sibling]),
            cluster,
            vm,
            RULE,
            ["slb-se-aaaaa", "slb-se-bbbbb"],
            dry_run=True,
        )
    cluster.ReconfigureComputeResource_Task.assert_not_called()
    assert "[dry run]" in caplog.text
