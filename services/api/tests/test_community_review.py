"""Community detections and playbooks are reviewed before anyone can see or install them.

POST /community/detections/publish and /community/playbooks/submit created entries with status APPROVED ("auto-approve for demo; change to PENDING in prod"), so any user's submission was
immediately listed for every tenant to install. For playbooks, which carry response actions, that is an unreviewed-code supply chain. Re-submitting an existing detection id also silently
replaced an approved entry. Plugins already did this correctly (pending, admin review, install refused until approved). Also fixed on the way: installing a community detection read d["title"],
which does not exist (entries store "name"), so every install was a KeyError / HTTP 500; and a detection had no review route at all.

Now: submissions start pending; unreviewed or rejected items are not listed, viewable or installable; admins approve or reject via PUT .../curate (rules:admin / playbooks:admin); an existing id is
never overwritten.
"""
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.endpoints import community

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


def client_as(role: str) -> TestClient:
    app = FastAPI()
    app.include_router(community.router)
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(
        user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role=role, email=f"{role}@example.test"
    )
    return TestClient(app)


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
