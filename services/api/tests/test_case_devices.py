import uuid
from types import SimpleNamespace as NS

from app.services.case_devices import build_case_devices

D1 = uuid.uuid4()


def _alert(hosts, source="huntress", device_url=None):
    raw = {"source": source}
    if device_url:
        raw["links"] = {"device_url": device_url}
    return NS(affected_hosts=hosts, raw_event=raw)


def test_a_machine_gets_the_alerts_own_link_and_the_link_each_tool_holds_for_it():
    devices = [NS(id=D1, hostname="PC-01", os="Windows 11")]
    sources = [NS(device_id=D1, vendor="ninjaone", details={"url": "https://app.ninjarmm.com/#/deviceDashboard/18/overview"}), NS(device_id=D1, vendor="huntress", details={})]
    out = build_case_devices([_alert(["pc-01"], device_url="https://acme.huntress.io/org/1/agents/9")], devices, sources)
    assert len(out) == 1 and out[0]["device_id"] == str(D1) and out[0]["os"] == "Windows 11"
    assert {(link["vendor"], link["label"]) for link in out[0]["links"]} == {("huntress", "Huntress"), ("ninjaone", "NinjaOne")}


def test_unsafe_addresses_are_dropped_and_a_machine_with_no_record_still_lists():
    out = build_case_devices([_alert(["PC-02"], device_url="javascript:alert(1)")], [], [])
    assert out == [{"hostname": "PC-02", "device_id": None, "os": None, "alerts": 1, "links": []}]
    devices = [NS(id=D1, hostname="PC-03", os=None)]
    out = build_case_devices([_alert(["PC-03"])], devices, [NS(device_id=D1, vendor="ninjaone", details={"url": "http://insecure.example/x"})])
    assert out[0]["links"] == []


def test_alerts_naming_the_same_machine_are_counted_once_per_alert_and_sorted():
    out = build_case_devices([_alert(["b-host", "A-host"]), _alert(["B-HOST"])], [], [])
    assert [d["hostname"] for d in out] == ["A-host", "b-host"] and out[1]["alerts"] == 2


def test_a_screenconnect_machine_gets_an_open_in_screenconnect_link_from_its_record():
    devices = [NS(id=D1, hostname="PC-07", os="Windows 11")]
    sources = [NS(device_id=D1, vendor="screenconnect", details={"url": "https://liveoakit.screenconnect.com/Host#Access/All%20Machines//abc/Join"})]
    out = build_case_devices([_alert(["PC-07"])], devices, sources)
    assert [(link["vendor"], link["label"]) for link in out[0]["links"]] == [("screenconnect", "ScreenConnect")]
