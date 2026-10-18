"""GET /graph: the overview the Attack Graph page draws, built from alerts. It was a page that said 'not available in this build' because the route did not exist."""

from __future__ import annotations

from app.api.v1.endpoints.graph import _MAX_ENTITIES_PER_KIND, _MAX_TECHNIQUES, build_overview


def alert(severity="medium", hosts=(), users=(), ips=(), techniques=()):
    return {"severity": severity, "affected_hosts": list(hosts), "affected_users": list(users), "affected_ips": list(ips), "mitre_techniques": list(techniques)}


def by_id(graph):
    return {n["id"]: n for n in graph["nodes"]}


def test_no_alerts_is_an_empty_graph_not_invented_nodes():
    assert build_overview([]) == {"nodes": [], "edges": []}


def test_entities_and_techniques_become_nodes_and_an_edge_says_how_many_alerts_joined_them():
    g = build_overview([alert("high", hosts=["WS-1"], users=["ann"], techniques=["T1059"]), alert("low", hosts=["WS-1"], techniques=["T1059"])])
    nodes = by_id(g)
    assert set(nodes) == {"host:WS-1", "user:ann", "technique:T1059"}
    assert nodes["host:WS-1"]["kind"] == "host" and nodes["host:WS-1"]["attributes"]["alerts"] == 2
    host_edge = next(e for e in g["edges"] if e["source"] == "host:WS-1")
    assert host_edge["target"] == "technique:T1059" and host_edge["weight"] == 2
    assert next(e for e in g["edges"] if e["source"] == "user:ann")["weight"] == 1


def test_a_node_carries_its_worst_severity_and_a_risk_score_from_it():
    g = build_overview([alert("low", hosts=["h"]), alert("critical", hosts=["h"]), alert("medium", hosts=["h"])])
    n = by_id(g)["host:h"]
    assert n["severity"] == "critical" and n["riskScore"] == 90


def test_techniques_given_as_objects_or_strings_both_count_and_junk_is_ignored():
    g = build_overview([alert(hosts=["h"], techniques=["T1", {"id": "T2"}, {"technique_id": "T3"}, {"name": "no id"}, "", None, 5])])
    assert {n["id"] for n in g["nodes"] if n["kind"] == "technique"} == {"technique:T1", "technique:T2", "technique:T3"}


def test_the_entity_filter_keeps_only_alerts_that_name_it_ignoring_case():
    alerts = [alert(hosts=["WS-1"], techniques=["T1"]), alert(hosts=["WS-2"], techniques=["T2"])]
    g = build_overview(alerts, entity="ws-1")
    assert set(by_id(g)) == {"host:WS-1", "technique:T1"}
    assert build_overview(alerts, entity="nobody") == {"nodes": [], "edges": []}


def test_only_the_busiest_entities_and_techniques_are_kept():
    many = [alert(hosts=[f"h{i:03d}"], techniques=[f"T{i:03d}"]) for i in range(60)]
    many += [alert(hosts=["busy"], techniques=["TBUSY"])] * 5
    g = build_overview(many)
    hosts = [n for n in g["nodes"] if n["kind"] == "host"]
    techniques = [n for n in g["nodes"] if n["kind"] == "technique"]
    assert len(hosts) == _MAX_ENTITIES_PER_KIND and "host:busy" in by_id(g)
    assert len(techniques) <= _MAX_TECHNIQUES and "technique:TBUSY" in by_id(g)
    ids = by_id(g)
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"]), "an edge pointed at a node that was cut"


def test_an_unknown_severity_is_treated_as_info():
    assert by_id(build_overview([alert("weird", hosts=["h"])]))["host:h"]["severity"] == "info"


def test_numeric_and_blank_names_are_handled():
    g = build_overview([alert(ips=["10.0.0.1", "  ", 5])])
    assert set(by_id(g)) == {"ip:10.0.0.1", "ip:5"}


def test_a_host_and_the_user_on_the_same_alert_are_linked_even_when_no_technique_is_known():
    g = build_overview([alert(hosts=["WS-1"], users=["ann"]), alert(hosts=["WS-1"], users=["ann"]), alert(hosts=["WS-2"])])
    link = next(e for e in g["edges"] if e["label"] == "seen on the same alert")
    assert {link["source"], link["target"]} == {"host:WS-1", "user:ann"} and link["weight"] == 2
    assert not any("WS-2" in e["source"] + e["target"] for e in g["edges"]), "a lone host is a node with no edge, not a made-up link"


def test_two_entities_of_the_same_kind_on_one_alert_are_not_linked():
    g = build_overview([alert(hosts=["a", "b"])])
    assert g["edges"] == []
