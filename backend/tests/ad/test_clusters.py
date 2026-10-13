"""Кластеры Windows по SPN: учётка кластера, роли (привязка по создателю), узлы; обычный компьютер без находки."""
from api.modules.ad.core.checks.clusters import cluster_kind
from tests.ad.mini import computer, mini_export, rid, run

CNO = ["MSServerCluster/clu1", "MSClusterVirtualServer/clu1", "MSServerClusterMgmtAPI/clu1.corp.local", "HOST/clu1"]
VCO = ["MSClusterVirtualServer/{0}", "MSServerClusterMgmtAPI/{0}.corp.local", "HOST/{0}"]
NODE = ["MSServerClusterMgmtAPI/{0}.corp.local", "WSMAN/{0}", "TERMSRV/{0}", "HOST/{0}"]


def vco(name: str) -> list[str]:
    return [s.format(name) for s in VCO]


def test_cluster_kind_by_spn():
    assert cluster_kind(CNO) == "cluster"
    assert cluster_kind(vco("fs1")) == "role"
    assert cluster_kind([s.format("n1") for s in NODE]) == "node"
    assert cluster_kind(["HOST/ws1", "TERMSRV/ws1"]) is None
    assert cluster_kind([]) is None


def test_clusters_roles_and_nodes():
    exp = mini_export([
        computer("CLU1", 1101, spn=CNO, operatingSystem=""),
        computer("FS1", 1102, spn=vco("fs1"), creatorSid=rid(1101)),
        computer("SQLAG1", 1103, spn=vco("sqlag1"), creatorSid=rid(1101), uac=4098, operatingSystem="Windows Server 2019 Datacenter"),
        computer("ORPHAN", 1104, spn=vco("orphan")),  # без создателя — кластер не определён
        computer("N1", 1105, spn=[s.format("n1") for s in NODE], operatingSystem="Windows Server 2019 Datacenter"),
        computer("WS1", 1106, spn=["HOST/ws1"]),
    ])
    found = {f.details["sam"]: f for f in run("Clusters", exp)}
    assert set(found) == {"CLU1$", "FS1$", "SQLAG1$", "ORPHAN$", "N1$"}
    assert all(f.severity == "Info" for f in found.values())
    assert len({f.key for f in found.values()}) == 5

    clu = found["CLU1$"].details
    assert (clu["kind"], clu["kind_title"]) == ("cluster", "кластер")
    assert clu["roles"] == ["FS1$", "SQLAG1$"] and clu["roles_disabled"] == 1 and clu["enabled"] is True

    assert found["FS1$"].details["cluster"] == "CLU1$" and "details" not in found["FS1$"].details
    sql = found["SQLAG1$"].details
    assert sql["enabled"] is False and sql["details"].startswith("выключена") and sql["os"] == "Windows Server 2019 Datacenter"
    assert found["ORPHAN$"].details["cluster"] == "не определён"
    assert found["N1$"].details["kind"] == "node" and found["N1$"].details["fqdn"] == "n1.corp.local"
