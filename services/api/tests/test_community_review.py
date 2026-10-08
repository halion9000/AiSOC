"""Community detections and playbooks are reviewed before anyone can see or install them.

POST /community/detections/publish and /community/playbooks/submit created entries with status APPROVED ("auto-approve for demo; change to PENDING in prod"), so any user's submission was
immediately listed for every tenant to install. For playbooks, which carry response actions, that is an unreviewed-code supply chain. Re-submitting an existing detection id also silently
replaced an approved entry. Plugins already did this correctly (pending, admin review, install refused until approved). Also fixed on the way: installing a community detection read d["title"],
which does not exist (entries store "name"), so every install was a KeyError / HTTP 500; and a detection had no review route at all.

Now: submissions start pending; unreviewed or rejected items are not listed, viewable or installable; admins approve or reject via PUT .../curate (rules:admin / playbooks:admin); an existing id is
never overwritten.
"""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import community
from app.api.v1.endpoints import playbooks as playbooks_api
from app.db.database import Base
from app.models.detection_rule import DetectionRule

SIGMA = """title: Suspicious PowerShell
id: {rule_id}
status: experimental
description: Encoded PowerShell command line
author: Someone
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: '*powershell.exe'
  condition: selection
"""
PREFIX = community.router.prefix


DB = SimpleNamespace(factory=None, sync=None)
PROXY = SimpleNamespace(calls=[], result={"id": "pb-1"}, error=None)


def client_as(role: str, tenant_id: uuid.UUID | None = None) -> TestClient:
    tenant_id = tenant_id or uuid.uuid4()
    app = FastAPI()
    app.include_router(community.router)
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(
        user_id=uuid.uuid4(), tenant_id=tenant_id, role=role, email=f"{role}@example.test"
    )

    async def real_session():
        async with DB.factory() as session:
            yield session

    app.dependency_overrides[deps.get_db] = real_session
    return TestClient(app)


def installed_rules() -> list[DetectionRule]:
    with Session(DB.sync) as s:
        return list(s.scalars(select(DetectionRule)).all())


@pytest.fixture(autouse=True)
def database(tmp_path):
    """A real (file-backed SQLite) database holding the detection_rules table, so installs are checked against actual rows."""
    path = tmp_path / "community.db"
    DB.sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(DB.sync, tables=[DetectionRule.__table__])
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool)
    DB.factory = async_sessionmaker(engine, expire_on_commit=False)
    yield
    DB.sync.dispose()


@pytest.fixture(autouse=True)
def fake_playbook_engine(monkeypatch):
    """Stand in for the agents service behind the API's playbook proxy."""
    PROXY.calls.clear()
    PROXY.result, PROXY.error = {"id": "pb-1"}, None

    async def fake_proxy(method, path, **kwargs):
        PROXY.calls.append((method, path, kwargs))
        if PROXY.error is not None:
            raise PROXY.error
        return PROXY.result

    monkeypatch.setattr(playbooks_api, "_proxy", fake_proxy)


@pytest.fixture(autouse=True)
def clean_stores():
    community._community_detections.clear()
    community._community_playbooks.clear()
    yield
    community._community_detections.clear()
    community._community_playbooks.clear()


@pytest.fixture
def admin():
    return client_as("admin")


def submit_detection(c, rule_id=None):
    rule_id = rule_id or str(uuid.uuid4())
    r = c.post(f"{PREFIX}/detections/publish", content=SIGMA.format(rule_id=rule_id), headers={"content-type": "text/plain"})
    return rule_id, r


class TestDetections:
    def test_a_submission_is_pending_and_invisible_until_reviewed(self, admin):
        rule_id, r = submit_detection(admin)
        assert r.status_code == 201
        assert r.json()["status"] == "pending"
        assert "for review" in r.json()["message"]
        assert admin.get(f"{PREFIX}/detections").json()["items"] == []
        assert admin.get(f"{PREFIX}/detections/{rule_id}").status_code == 404

    def test_an_unreviewed_detection_cannot_be_installed(self, admin):
        rule_id, _ = submit_detection(admin)
        r = admin.post(f"{PREFIX}/detections/{rule_id}/install")
        assert r.status_code == 400 and "not approved" in r.json()["detail"]
        assert community._community_detections[rule_id]["install_count"] == 0

    def test_once_approved_it_is_listed_viewable_and_installable(self, admin):
        rule_id, _ = submit_detection(admin)
        assert admin.put(f"{PREFIX}/detections/{rule_id}/curate", json={"action": "approve"}).json() == {"id": rule_id, "status": "approved"}
        assert [d["id"] for d in admin.get(f"{PREFIX}/detections").json()["items"]] == [rule_id]
        assert admin.get(f"{PREFIX}/detections/{rule_id}").status_code == 200
        installed = admin.post(f"{PREFIX}/detections/{rule_id}/install")
        assert installed.status_code == 200  # this was a KeyError ('title') on every install
        assert installed.json()["title"] == "Suspicious PowerShell"
        assert community._community_detections[rule_id]["install_count"] == 1

    def test_a_rejected_detection_stays_hidden_and_uninstallable(self, admin):
        rule_id, _ = submit_detection(admin)
        assert admin.put(f"{PREFIX}/detections/{rule_id}/curate", json={"action": "reject", "notes": "too noisy"}).json()["status"] == "rejected"
        assert admin.get(f"{PREFIX}/detections").json()["items"] == []
        assert admin.get(f"{PREFIX}/detections/{rule_id}").status_code == 404
        assert admin.post(f"{PREFIX}/detections/{rule_id}/install").status_code == 400

    def test_resubmitting_an_existing_id_cannot_replace_an_approved_rule(self, admin):
        rule_id, _ = submit_detection(admin)
        admin.put(f"{PREFIX}/detections/{rule_id}/curate", json={"action": "approve"})
        again = admin.post(f"{PREFIX}/detections/publish", content=SIGMA.format(rule_id=rule_id).replace("powershell", "evil"), headers={"content-type": "text/plain"})
        assert again.status_code == 409
        assert community._community_detections[rule_id]["status"] == community.PublishStatus.APPROVED
        assert "evil" not in community._community_detections[rule_id]["sigma_yaml"]

    def test_curating_an_unknown_id_is_a_404(self, admin):
        assert admin.put(f"{PREFIX}/detections/nope/curate", json={"action": "approve"}).status_code == 404

    def test_only_an_admin_can_curate_detections(self, admin):
        rule_id, _ = submit_detection(admin)
        # tenant_admin and threat_hunter CAN submit (rules:write) but must not be able to curate: that is what separates "write" from "admin"
        for role in ("tenant_admin", "threat_hunter", "viewer"):
            assert client_as(role).put(f"{PREFIX}/detections/{rule_id}/curate", json={"action": "approve"}).status_code == 403, role
        assert community._community_detections[rule_id]["status"] == community.PublishStatus.PENDING


class TestPlaybooks:
    def submit(self, c, name="Isolate host"):
        return c.post(f"{PREFIX}/playbooks/submit", json={"name": name, "description": "d", "steps": [{"action": "isolate_host"}]})

    def test_a_submission_is_pending_and_invisible_until_reviewed(self, admin):
        r = self.submit(admin)
        assert r.status_code == 201
        assert r.json()["status"] == "pending" and "for review" in r.json()["message"]
        assert admin.get(f"{PREFIX}/playbooks").json()["items"] == []

    def test_an_unreviewed_playbook_cannot_be_installed(self, admin):
        pid = self.submit(admin).json()["id"]
        r = admin.post(f"{PREFIX}/playbooks/{pid}/install")
        assert r.status_code == 400 and "not approved" in r.json()["detail"]
        assert community._community_playbooks[pid]["install_count"] == 0

    def test_once_approved_it_is_listed_and_installable(self, admin):
        pid = self.submit(admin).json()["id"]
        assert admin.put(f"{PREFIX}/playbooks/{pid}/curate", json={"action": "approve"}).json()["status"] == "approved"
        assert [p["id"] for p in admin.get(f"{PREFIX}/playbooks").json()["items"]] == [pid]
        assert admin.post(f"{PREFIX}/playbooks/{pid}/install").status_code == 200

    def test_a_rejected_playbook_stays_hidden(self, admin):
        pid = self.submit(admin).json()["id"]
        admin.put(f"{PREFIX}/playbooks/{pid}/curate", json={"action": "reject"})
        assert admin.get(f"{PREFIX}/playbooks").json()["items"] == []
        assert admin.post(f"{PREFIX}/playbooks/{pid}/install").status_code == 400

    def test_only_an_admin_can_curate_playbooks(self, admin):
        pid = self.submit(admin).json()["id"]
        for role in ("tenant_admin", "viewer"):  # tenant_admin can submit (playbooks:write) but must not curate (playbooks:admin)
            assert client_as(role).put(f"{PREFIX}/playbooks/{pid}/curate", json={"action": "approve"}).status_code == 403, role
        assert community._community_playbooks[pid]["status"] == community.PublishStatus.PENDING


class TestInstallingReallyInstalls:
    """install used to only bump a counter and answer "installed". It now creates what it says."""

    def approved_detection(self, level=None):
        admin = client_as("admin")
        rule_id, _ = submit_detection(admin)
        if level:
            community._community_detections[rule_id]["level"] = level
        admin.put(f"{PREFIX}/detections/{rule_id}/curate", json={"action": "approve"})
        return rule_id

    def test_a_detection_becomes_a_real_rule_in_the_installing_tenant_in_testing_status(self):
        rule_id = self.approved_detection()
        tenant = uuid.uuid4()
        response = client_as("admin", tenant).post(f"{PREFIX}/detections/{rule_id}/install")
        assert response.status_code == 200
        rows = installed_rules()
        assert len(rows) == 1
        rule = rows[0]
        assert response.json()["rule_id"] == str(rule.id)
        assert rule.tenant_id == tenant
        assert rule.name == "Suspicious PowerShell"
        assert rule.rule_language == "sigma"
        assert "Image: '*powershell.exe'" in rule.rule_body
        assert rule.category == "process_creation"
        assert rule.status == "testing", "an installed community rule must not start firing"
        assert rule.provenance["source"] == "community"
        assert rule.provenance["community_detection_id"] == rule_id
        assert community._community_detections[rule_id]["install_count"] == 1

    def test_installing_twice_in_one_tenant_does_not_duplicate_the_rule(self):
        rule_id = self.approved_detection()
        tenant = uuid.uuid4()
        client = client_as("admin", tenant)
        assert client.post(f"{PREFIX}/detections/{rule_id}/install").status_code == 200
        again = client.post(f"{PREFIX}/detections/{rule_id}/install")
        assert again.status_code == 409 and "already installed" in again.json()["detail"]
        assert len(installed_rules()) == 1
        assert community._community_detections[rule_id]["install_count"] == 1

    def test_two_tenants_each_get_their_own_rule(self):
        rule_id = self.approved_detection()
        a, b = uuid.uuid4(), uuid.uuid4()
        assert client_as("admin", a).post(f"{PREFIX}/detections/{rule_id}/install").status_code == 200
        assert client_as("admin", b).post(f"{PREFIX}/detections/{rule_id}/install").status_code == 200
        assert sorted(str(r.tenant_id) for r in installed_rules()) == sorted([str(a), str(b)])

    def test_an_unapproved_detection_creates_no_rule(self):
        admin = client_as("admin")
        rule_id, _ = submit_detection(admin)
        assert admin.post(f"{PREFIX}/detections/{rule_id}/install").status_code == 400
        assert installed_rules() == []

    @pytest.mark.parametrize(
        "level, expected",
        [("critical", "critical"), ("high", "high"), ("low", "low"), ("informational", "info"), ("bogus", "medium"), (None, "medium")],
    )
    def test_the_sigma_level_maps_to_a_rule_severity(self, level, expected):
        assert community._rule_severity(level) == expected

    def test_a_playbook_is_created_in_the_engine_disabled(self):
        admin = client_as("admin")
        pid = admin.post(f"{PREFIX}/playbooks/submit", json={"name": "Isolate host", "steps": [{"action": "isolate_host"}], "enabled": True}).json()["id"]
        admin.put(f"{PREFIX}/playbooks/{pid}/curate", json={"action": "approve"})
        response = admin.post(f"{PREFIX}/playbooks/{pid}/install")
        assert response.status_code == 200
        assert response.json()["playbook_id"] == "pb-1"
        (method, path, kwargs), = PROXY.calls
        assert (method, path) == ("POST", "")
        assert kwargs["json"]["name"] == "Isolate host" and kwargs["json"]["steps"] == [{"action": "isolate_host"}]
        assert kwargs["json"]["enabled"] is False, "an installed community playbook must not start live"
        assert community._community_playbooks[pid]["definition"]["enabled"] is True  # the catalog entry itself is not altered
        assert community._community_playbooks[pid]["install_count"] == 1

    @pytest.mark.parametrize("status_code", [422, 503])
    def test_when_the_engine_refuses_the_install_fails_and_is_not_counted(self, status_code):
        admin = client_as("admin")
        pid = admin.post(f"{PREFIX}/playbooks/submit", json={"name": "Bad playbook"}).json()["id"]
        admin.put(f"{PREFIX}/playbooks/{pid}/curate", json={"action": "approve"})
        PROXY.error = HTTPException(status_code=status_code, detail="engine said no")
        response = admin.post(f"{PREFIX}/playbooks/{pid}/install")
        assert response.status_code == status_code
        assert community._community_playbooks[pid]["install_count"] == 0

    def test_a_community_plugin_cannot_be_installed_because_no_package_is_stored(self):
        community._community_plugins["plug-1"] = {"id": "plug-1", "status": community.PublishStatus.APPROVED, "install_count": 0, "version": "1.0.0"}
        response = client_as("admin").post(f"{PREFIX}/plugins/plug-1/install")
        assert response.status_code == 501
        assert "cannot be installed yet" in response.json()["detail"]
        assert community._community_plugins["plug-1"]["install_count"] == 0
        community._community_plugins.pop("plug-1")

    def test_an_unapproved_plugin_is_still_refused_as_before(self):
        community._community_plugins["plug-2"] = {"id": "plug-2", "status": community.PublishStatus.PENDING, "install_count": 0, "version": "1.0.0"}
        assert client_as("admin").post(f"{PREFIX}/plugins/plug-2/install").status_code == 400
        community._community_plugins.pop("plug-2")
