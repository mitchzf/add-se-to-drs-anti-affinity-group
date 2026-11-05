"""End-to-end tests: does an alert for a new SE create the DRS rule?

These run main() as Avi would, with the alert JSON as the first argument.
Only the outside systems are faked: the Avi API (which SEs are in the SE
group) and vCenter (the VMs and the cluster). Everything between, including
add_vm_to_anti_affinity_rule, is the real code.
"""

# pytest fixtures are passed as arguments with the same names as the
# fixtures.
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
from types import SimpleNamespace
from unittest import mock

import pytest
from pyVmomi import vim

from conftest import (
    FakeAviSession,
    FakeCluster,
    FakeContent,
    FakeResponse,
    FakeVM,
)

CONTROLLER = "avi.example.com"
CLOUD = "Default-Cloud"
GROUP = "Default-Group"
RULE = f"avi_se_antiaffinity_{CONTROLLER}_{CLOUD}_{GROUP}"
NEW_SE = "slb-se-eyiec"
API = "https://10.0.0.1/api"
ALERT = json.dumps(
    {
        "events": [
            {
                "event_id": "CREATED_SE",
                "event_details": {
                    "spawn_se_details": {
                        "se_name": NEW_SE,
                        "se_grp_name": GROUP,
                        "cloud_name": CLOUD,
                    }
                },
            }
        ]
    }
)


@pytest.fixture
def env(cs, monkeypatch):
    """Fake the Avi API and vCenter; returns a function that sets them up.

    setup(avi_ses, cluster_vm_names) makes the Avi API list ``avi_ses`` as
    the SE group's SEs, and puts a VM for each of ``cluster_vm_names`` in
    one cluster. The Avi API names the controller cluster ``CONTROLLER``.
    It returns the cluster and the fake Avi session.
    """
    wait = mock.Mock()
    monkeypatch.setattr(cs, "WaitForTask", wait)
    monkeypatch.setattr(
        cs,
        "parse_vcenter_credentials",
        lambda args: ("vc.example.test", "user", "pw"),
    )
    monkeypatch.setattr(cs, "Disconnect", mock.Mock())

    def setup(avi_ses, cluster_vm_names, rules=()):
        cluster = FakeCluster("domain-c1", rules=rules)
        host = SimpleNamespace(parent=cluster)
        vms = [
            FakeVM(f"vm-{i}", name, host=host)
            for i, name in enumerate(cluster_vm_names)
        ]
        content = FakeContent(all_vms=vms, cluster_vms=vms)
        si = mock.Mock(RetrieveContent=mock.Mock(return_value=content))
        monkeypatch.setattr(cs, "SmartConnect", mock.Mock(return_value=si))
        session = FakeAviSession(
            objects={("serviceenginegroup", GROUP): {"uuid": "seg-1"}},
            lists={
                "serviceengine": [
                    {
                        "name": n,
                        "se_group_ref": f"{API}/serviceenginegroup/seg-1",
                    }
                    for n in avi_ses
                ]
                # SEs of another SE group, which must not count.
                + [
                    {
                        "name": n,
                        "se_group_ref": f"{API}/serviceenginegroup/seg-9",
                    }
                    for n in ("slb-se-zzzzz", "slb-se-yyyyy")
                ]
            },
            responses={
                "cluster": FakeResponse(
                    json.dumps({"name": CONTROLLER}).encode()
                )
            },
        )
        monkeypatch.setattr(cs, "get_avi_session", lambda: session)
        return SimpleNamespace(
            cluster=cluster, vms=vms, session=session, wait=wait
        )

    return setup


def created_rule(cluster):
    """The rule the script asked vCenter to create (exactly one)."""
    assert len(cluster.reconfigure_calls) == 1
    spec, modify = cluster.reconfigure_calls[0]
    assert modify is True
    (rule_spec,) = spec.rulesSpec
    assert rule_spec.operation == "add"
    assert isinstance(rule_spec.info, vim.cluster.AntiAffinityRuleSpec)
    return rule_spec.info


@pytest.mark.parametrize(
    "group_ses",
    [
        [NEW_SE, "slb-se-abcde"],
        [NEW_SE, "slb-se-abcde", "slb-se-fghij"],
        [NEW_SE, "slb-se-abcde", "slb-se-fghij", "slb-se-klmno"],
    ],
    ids=["2-ses", "3-ses", "4-ses"],
)
def test_rule_created_with_two_or_more_ses(cs, env, group_ses):
    """2+ SEs in the group and the cluster: the rule is created with all."""
    fake = env(group_ses, group_ses + ["web01"])

    assert cs.main([ALERT]) == 0

    rule = created_rule(fake.cluster)
    assert rule.name == RULE
    assert rule.name == (
        "avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group"
    )
    assert rule.enabled is True and rule.userCreated is True
    assert sorted(vm.name for vm in rule.vm) == sorted(group_ses)
    fake.wait.assert_called_once_with("task-1")
    # The group's SEs came from the Avi API, looked up by the alert's group.
    assert (
        "get_object_by_name",
        "serviceenginegroup",
        GROUP,
        {"cloud_ref.name": CLOUD},
    ) in fake.session.calls


def test_rule_created_when_avi_does_not_list_new_se_yet(cs, env):
    """The new SE counts toward the 2 even if Avi doesn't list it yet."""
    fake = env(["slb-se-abcde"], [NEW_SE, "slb-se-abcde"])

    assert cs.main([ALERT]) == 0

    assert sorted(vm.name for vm in created_rule(fake.cluster).vm) == [
        "slb-se-abcde",
        NEW_SE,
    ]


@pytest.mark.parametrize(
    "avi_ses", [[NEW_SE], []], ids=["only-new-se", "none-listed"]
)
def test_rule_not_created_with_one_se(cs, env, avi_ses, caplog):
    """1 SE in the group: no rule, even with other SE VMs in the cluster.

    slb-se-zzzzz is in the cluster but belongs to another SE group.
    """
    fake = env(avi_ses, [NEW_SE, "slb-se-zzzzz"])

    with caplog.at_level("INFO"):
        assert cs.main([ALERT]) == 0

    assert not fake.cluster.reconfigure_calls
    assert "is the only SE in its SE group" in caplog.text


def test_rule_not_created_when_other_ses_are_in_another_cluster(
    cs, env, caplog
):
    """2 SEs, but the other one isn't in this cluster: no rule yet."""
    fake = env([NEW_SE, "slb-se-abcde"], [NEW_SE])

    with caplog.at_level("INFO"):
        assert cs.main([ALERT]) == 0

    assert not fake.cluster.reconfigure_calls
    assert "the rule will be created when the next SE is added" in caplog.text


def test_existing_rule_gets_new_se(cs, env):
    """If the rule exists, the new SE is added to it."""
    fake = env([NEW_SE, "slb-se-abcde"], [NEW_SE, "slb-se-abcde"])
    existing = vim.cluster.AntiAffinityRuleSpec(
        key=7, name=RULE, enabled=True, vm=[fake.vms[1]]
    )
    fake.cluster.configurationEx.rule.append(existing)

    assert cs.main([ALERT]) == 0

    ((spec, _),) = fake.cluster.reconfigure_calls
    (rule_spec,) = spec.rulesSpec
    assert rule_spec.operation == "edit" and rule_spec.info.key == 7
    assert [vm.name for vm in rule_spec.info.vm] == ["slb-se-abcde", NEW_SE]


def test_dry_run_reports_rule_without_creating_it(cs, env, caplog):
    fake = env([NEW_SE, "slb-se-abcde"], [NEW_SE, "slb-se-abcde"])

    with caplog.at_level("INFO"):
        assert cs.main([ALERT, "--dry-run"]) == 0

    assert not fake.cluster.reconfigure_calls
    assert f"[dry run] Creating rule '{RULE}' with" in caplog.text


def test_se_group_members_option_creates_rule(cs, env):
    """The local-testing path: options instead of the Avi API."""
    fake = env([], [NEW_SE, "slb-se-abcde"])

    argv = [ALERT, "--se-group-members", NEW_SE, "slb-se-abcde"]
    assert cs.main(argv + ["--controller-fqdn", "ctl.example.net"]) == 0

    rule = created_rule(fake.cluster)
    assert rule.name == f"avi_se_antiaffinity_ctl.example.net_{CLOUD}_{GROUP}"
    assert len(rule.vm) == 2
    assert not fake.session.calls


def test_existing_rule_gets_all_missing_group_ses(cs, env):
    """The rule gets every group SE it's missing, not just the new one.

    slb-se-abcde is already in the rule; slb-se-fghij was missed (say, its
    alert was throttled). Both it and the new SE are added, once each.
    """
    group = [NEW_SE, "slb-se-abcde", "slb-se-fghij"]
    fake = env(group, group + ["web01"])
    existing = vim.cluster.AntiAffinityRuleSpec(
        key=7, name=RULE, enabled=True, vm=[fake.vms[1]]
    )
    fake.cluster.configurationEx.rule.append(existing)

    assert cs.main([ALERT]) == 0

    ((spec, _),) = fake.cluster.reconfigure_calls
    (rule_spec,) = spec.rulesSpec
    assert rule_spec.operation == "edit" and rule_spec.info.key == 7
    names = [vm.name for vm in rule_spec.info.vm]
    assert sorted(names) == sorted(group)
    assert len(names) == len(set(names))


def test_rule_unchanged_when_it_has_all_group_ses(cs, env, caplog):
    fake = env([NEW_SE, "slb-se-abcde"], [NEW_SE, "slb-se-abcde"])
    existing = vim.cluster.AntiAffinityRuleSpec(
        key=7, name=RULE, enabled=True, vm=list(fake.vms)
    )
    fake.cluster.configurationEx.rule.append(existing)

    with caplog.at_level("INFO"):
        assert cs.main([ALERT]) == 0

    assert not fake.cluster.reconfigure_calls
    assert "nothing to do" in caplog.text


def test_second_se_creates_rule_using_alert_se_group_uuid(cs, env):
    """The alert's obj_uuid picks the SE group, so Default-Group in another
    cloud can't be found by mistake. The second SE creates the rule."""
    fake = env([], [NEW_SE, "slb-se-abcde"])
    seg_ref = f"{API}/serviceenginegroup/serviceenginegroup-seg-2"
    fake.session.lists["serviceengine"] += [
        {"name": "slb-se-abcde", "se_group_ref": seg_ref},
        {"name": NEW_SE, "se_group_ref": seg_ref},
    ]
    alert = json.loads(ALERT)
    alert["events"][0]["obj_uuid"] = "serviceenginegroup-seg-2"

    assert cs.main([json.dumps(alert)]) == 0

    rule = created_rule(fake.cluster)
    assert sorted(vm.name for vm in rule.vm) == ["slb-se-abcde", NEW_SE]
    assert not [c for c in fake.session.calls if c[0] == "get_object_by_name"]


def test_subsequent_ses_are_each_added(cs, env):
    """SEs 2, 3 and 4 are created one by one: the rule ends with all four."""
    group = [NEW_SE, "slb-se-abcde", "slb-se-fghij", "slb-se-klmno"]
    fake = env(group[:1], group)
    for count in range(2, 5):
        se_name = group[count - 1]
        fake.session.lists["serviceengine"].append(
            {
                "name": se_name,
                "se_group_ref": f"{API}/serviceenginegroup/seg-1",
            }
        )
        alert = json.loads(ALERT)
        alert["events"][0]["event_details"]["spawn_se_details"][
            "se_name"
        ] = se_name
        assert cs.main([json.dumps(alert)]) == 0
        # Apply the change, as vCenter would.
        spec, _ = fake.cluster.reconfigure_calls[-1]
        (rule_spec,) = spec.rulesSpec
        rules = fake.cluster.configurationEx.rule
        rules[:] = [r for r in rules if r.name != RULE]
        rule_spec.info.key = 7
        rules.append(rule_spec.info)
        assert sorted(vm.name for vm in rule_spec.info.vm) == sorted(
            group[:count]
        )
    assert [
        s.rulesSpec[0].operation for s, _ in fake.cluster.reconfigure_calls
    ] == [
        "add",
        "edit",
        "edit",
    ]


def test_se_in_another_cluster_is_reported(cs, env, caplog):
    """The group's other SE runs in another cluster: no rule, a warning."""
    fake = env([NEW_SE, "slb-se-abcde"], [NEW_SE, "slb-se-abcde"])
    fake.vms[1].runtime.host = SimpleNamespace(
        parent=FakeCluster("domain-c2", name="cl2")
    )

    with caplog.at_level("INFO"):
        assert cs.main([ALERT]) == 0

    assert not fake.cluster.reconfigure_calls
    assert "'slb-se-abcde' is in cluster 'cl2', not 'cl1'" in caplog.text
