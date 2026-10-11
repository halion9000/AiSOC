"""The community catalog (plugins, detections, playbooks) is stored in the database: submissions, approvals, install counts and ratings survive an API restart.

The endpoints kept three module-level dictionaries, so every restart silently discarded every submission, every approval (including items an admin had already approved), every install count and every
rating. Each call here uses its own session on a BRAND-NEW engine over the same database file, so "did X, then read it back" is genuinely "did X, then the process restarted".
Also pinned: a plugin resubmitted under an existing id no longer overwrites the existing entry (it used to); the submitted package bytes are no longer held in memory under "_tarball" (only the SHA-256 is
recorded); the submitting tenant is recorded; and the read-modify-write paths take a row lock, but the playbook install does NOT hold one across the call to the playbook engine.
"""
import asyncio
import base64
import hashlib
import json
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1.endpoints import community
from app.api.v1.endpoints import playbooks as playbooks_api
from app.db.database import Base
from app.models.community_catalog import CommunityCatalogItem
from app.models.detection_rule import DetectionRule
from app.models.tenant import Tenant

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


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "catalog.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine, tables=[Tenant.__table__, DetectionRule.__table__, CommunityCatalogItem.__table__])
    engine.dispose()
    return path


def run(db_path, fn):
    """Run `fn(session)` in its own session on a BRAND-NEW engine: a separate request, or a restarted process."""

    async def main():
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def person(tenant_id=None):
    return SimpleNamespace(user_id=uuid.uuid4(), tenant_id=tenant_id or uuid.uuid4(), email="someone@example.com", role="admin")


def row(db_path, kind, item_id):
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            return s.get(CommunityCatalogItem, (kind, item_id))
    finally:
        engine.dispose()


class FakeRequest:
    def __init__(self, body: bytes, manifest: dict):
        self.headers = {"X-Plugin-Signature": base64.b64encode(b"sig").decode(), "X-Plugin-Manifest": json.dumps(manifest)}
        self._body = body

    async def body(self) -> bytes:
        return self._body


def approve(kind, item_id):
    review = community.ReviewAction(action="approve")
    fns = {
        "detection": lambda s: community.curate_community_detection(item_id, review, current_user=person(), db=s),
        "playbook": lambda s: community.curate_community_playbook(item_id, review, current_user=person(), db=s),
        "plugin": lambda s: community.review_community_plugin(item_id, review, current_user=person(), db=s),
    }
    return fns[kind]


def publish_detection(db_path, u, rule_id=None):
    rule_id = rule_id or str(uuid.uuid4())
    run(db_path, lambda s: community.publish_detection(content=SIGMA.format(rule_id=rule_id), current_user=u, db=s))
    return rule_id


def submit_playbook(db_path, u, name="Isolate host"):
    return run(db_path, lambda s: community.submit_playbook(definition={"name": name, "steps": [{"action": "isolate_host"}], "enabled": True}, current_user=u, db=s))["id"]


def publish_plugin(db_path, u, plugin_id="plug-1", body=b"PACKAGE-BYTES", version="1.0.0"):
    manifest = {"id": plugin_id, "name": "Enricher", "version": version}
    return run(db_path, lambda s: community.publish_plugin(request=FakeRequest(body, manifest), current_user=u, db=s))


def list_playbooks(db_path):
    return run(db_path, lambda s: community.list_community_playbooks(page=1, page_size=20, search=None, sort_by="install_count", db=s))


def list_detections(db_path):
    return run(db_path, lambda s: community.list_community_detections(page=1, page_size=20, search=None, logsource_category=None, logsource_product=None, level=None, sort_by="install_count", db=s))


def list_plugins(db_path):
    return run(db_path, lambda s: community.list_community_plugins(status_filter=None, plugin_type=None, tags=None, sort="install_count", order="desc", page=1, page_size=20, db=s))


class TestEverythingSurvivesARestart:
    def test_submissions_approvals_installs_and_ratings_are_still_there(self, db_path, monkeypatch):
        async def fake_proxy(method, path, **kwargs):
            return {"id": "engine-pb-1"}

        monkeypatch.setattr(playbooks_api, "_proxy", fake_proxy)
        u = person()
        rule_id = publish_detection(db_path, u)
        pid = submit_playbook(db_path, u)
        publish_plugin(db_path, u)
        run(db_path, approve("detection", rule_id))
        run(db_path, approve("playbook", pid))
        run(db_path, approve("plugin", "plug-1"))
        run(db_path, lambda s: community.install_community_detection(rule_id, current_user=u, db=s))
        run(db_path, lambda s: community.install_community_playbook(pid, current_user=u, db=s))
        for score in (5, 4):
            run(db_path, lambda s, score=score: community.rate_community_plugin("plug-1", community.RatingIn(score=score), current_user=person(), db=s))

        # ---- everything below is read through brand-new engines: the API "restarted" between each step above and each read ----
        (d,) = list_detections(db_path)["items"]
        assert d["id"] == rule_id and d["status"] == "approved" and d["install_count"] == 1
        (p,) = list_playbooks(db_path)["items"]
        assert p["id"] == pid and p["status"] == "approved" and p["install_count"] == 1
        (plugin,) = list_plugins(db_path).items
        assert plugin.id == "plug-1" and plugin.status == "approved"
        assert plugin.rating == 4.5 and plugin.rating_count == 2

    def test_a_pending_submission_survives_and_stays_hidden_until_it_is_approved(self, db_path):
        u = person()
        rule_id = publish_detection(db_path, u)
        pid = submit_playbook(db_path, u)
        assert list_detections(db_path)["items"] == [] and list_playbooks(db_path)["items"] == []
        assert row(db_path, "detection", rule_id).status == "pending"
        run(db_path, approve("detection", rule_id))  # approved after the "restart"
        run(db_path, approve("playbook", pid))
        assert [d["id"] for d in list_detections(db_path)["items"]] == [rule_id]
        assert [p["id"] for p in list_playbooks(db_path)["items"]] == [pid]

    def test_a_rejection_and_its_notes_survive(self, db_path):
        u = person()
        rule_id = publish_detection(db_path, u)
        run(db_path, lambda s: community.curate_community_detection(rule_id, community.ReviewAction(action="reject", notes="too noisy"), current_user=person(), db=s))
        r = row(db_path, "detection", rule_id)
        assert r.status == "rejected" and r.data["review_notes"] == "too noisy" and r.data["status"] == "rejected"
        assert list_detections(db_path)["items"] == []

    def test_install_counts_accumulate_across_requests(self, db_path):
        rule_id = publish_detection(db_path, person())
        run(db_path, approve("detection", rule_id))
        for tenant in (uuid.uuid4(), uuid.uuid4(), uuid.uuid4()):
            run(db_path, lambda s, t=tenant: community.install_community_detection(rule_id, current_user=person(t), db=s))
        assert row(db_path, "detection", rule_id).data["install_count"] == 3

    def test_the_running_average_is_right_across_separate_requests(self, db_path):
        publish_plugin(db_path, person())
        run(db_path, approve("plugin", "plug-1"))  # only an approved plugin can be rated
        for score in (5, 4, 3):
            run(db_path, lambda s, score=score: community.rate_community_plugin("plug-1", community.RatingIn(score=score), current_user=person(), db=s))
        assert row(db_path, "plugin", "plug-1").data["rating"] == 4.0
        assert row(db_path, "plugin", "plug-1").data["rating_count"] == 3


class TestSubmissionsNeverOverwrite:
    def test_resubmitting_a_plugin_id_cannot_replace_an_approved_plugin(self, db_path):
        u = person()
        publish_plugin(db_path, u, body=b"ORIGINAL", version="1.0.0")
        run(db_path, approve("plugin", "plug-1"))
        with pytest.raises(HTTPException) as err:
            publish_plugin(db_path, person(), body=b"MALICIOUS-REPLACEMENT", version="9.9.9")
        assert err.value.status_code == 409
        kept = row(db_path, "plugin", "plug-1")
        assert kept.status == "approved"
        assert kept.data["version"] == "1.0.0"
        assert kept.data["tarball_sha256"] == hashlib.sha256(b"ORIGINAL").hexdigest()

    def test_resubmitting_a_detection_id_is_still_refused(self, db_path):
        rule_id = publish_detection(db_path, person())
        with pytest.raises(HTTPException) as err:
            publish_detection(db_path, person(), rule_id=rule_id)
        assert err.value.status_code == 409
        assert len(list(_all_rows(db_path, "detection"))) == 1


def _all_rows(db_path, kind):
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            return [r for r in s.query(CommunityCatalogItem).filter_by(kind=kind).all()]
    finally:
        engine.dispose()


class TestPublishingAPlugin:
    def test_publishing_works_and_is_recorded_as_unverified(self, db_path):
        """It raised ImportError (HTTP 500) on EVERY call: it imported a Responder model that does not exist. With no registry of authors' signing keys, nothing can be verified."""
        result = publish_plugin(db_path, person())
        assert result == {"id": "plug-1", "status": "pending", "message": "Plugin submitted for review"}
        assert row(db_path, "plugin", "plug-1").data["verified"] is False

    def test_a_plugin_is_never_marked_verified_by_a_signature_nobody_can_check(self, db_path):
        publish_plugin(db_path, person(), plugin_id="a")
        publish_plugin(db_path, person(), plugin_id="b")
        assert [row(db_path, "plugin", i).data["verified"] for i in ("a", "b")] == [False, False]

    def test_missing_headers_are_still_refused(self, db_path):
        class NoHeaders:
            headers: dict = {}

            async def body(self) -> bytes:
                return b"x"

        with pytest.raises(HTTPException) as err:
            run(db_path, lambda s: community.publish_plugin(request=NoHeaders(), current_user=person(), db=s))
        assert err.value.status_code == 400

    def test_an_empty_package_is_still_refused(self, db_path):
        with pytest.raises(HTTPException) as err:
            publish_plugin(db_path, person(), body=b"")
        assert err.value.status_code == 400


class TestIntegrityErrorsAreNotAllDuplicates:
    """create() used to turn ANY IntegrityError into "already exists". A foreign-key fault (the submitting tenant does not exist) was reported as a duplicate id: a misleading message that
    would also hide a real fault. Found by running against real Postgres; SQLite does not enforce foreign keys unless asked, which is why these tests ask."""

    def create_with_foreign_keys_enforced(self, db_path, tenant_id, item_id="dup-test"):
        async def main():
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool)

            def enforce(dbapi_connection, _record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

            event.listen(engine.sync_engine, "connect", enforce)
            try:
                async with async_sessionmaker(engine, expire_on_commit=False)() as s:
                    await community.PLUGINS.create(s, item_id, {"id": item_id, "status": "pending"}, submitter_tenant_id=tenant_id)
            finally:
                await engine.dispose()

        return asyncio.run(main())

    def test_a_missing_submitter_tenant_is_its_own_error_not_a_duplicate(self, db_path):
        with pytest.raises(IntegrityError):  # the foreign-key fault itself, NOT ItemExists / HTTP 409 "already exists"
            self.create_with_foreign_keys_enforced(db_path, tenant_id=uuid.uuid4())
        assert row(db_path, "plugin", "dup-test") is None

    def test_a_real_duplicate_is_still_reported_as_one(self, db_path):
        engine = create_engine(f"sqlite:///{db_path}")
        tenant = uuid.uuid4()
        with Session(engine) as s:
            s.add(Tenant(id=tenant, name="T", slug="t-" + uuid.uuid4().hex[:6]))
            s.commit()
        engine.dispose()
        self.create_with_foreign_keys_enforced(db_path, tenant_id=tenant)
        with pytest.raises(community.ItemExists):
            self.create_with_foreign_keys_enforced(db_path, tenant_id=tenant)


class TestWhatIsRecorded:
    def test_the_package_bytes_are_not_kept_only_their_sha256(self, db_path):
        body = b"PACKAGE-BYTES"
        publish_plugin(db_path, person(), body=body)
        data = row(db_path, "plugin", "plug-1").data
        assert "_tarball" not in data
        assert data["tarball_sha256"] == hashlib.sha256(body).hexdigest()
        assert "PACKAGE-BYTES" not in json.dumps(data)
        # nothing else derived from the package either (a hex or base64 copy, say): the entry has exactly the expected keys
        assert set(data) == {
            "id", "name", "version", "plugin_type", "description", "author", "tags", "status", "install_count", "rating", "rating_count",
            "verified", "submitted_by", "submitted_at", "approved_at", "tarball_sha256",
        }
        assert body.hex() not in json.dumps(data) and base64.b64encode(body).decode() not in json.dumps(data)

    def test_the_submitting_tenant_is_recorded_for_every_kind(self, db_path):
        tenant = uuid.uuid4()
        u = person(tenant)
        rule_id = publish_detection(db_path, u)
        pid = submit_playbook(db_path, u)
        publish_plugin(db_path, u)
        assert row(db_path, "detection", rule_id).submitter_tenant_id == tenant
        assert row(db_path, "playbook", pid).submitter_tenant_id == tenant
        assert row(db_path, "plugin", "plug-1").submitter_tenant_id == tenant

    def test_ids_and_enums_are_stored_as_plain_json(self, db_path):
        u = person()
        publish_plugin(db_path, u)
        data = row(db_path, "plugin", "plug-1").data
        assert data["submitted_by"] == str(u.user_id)
        assert data["status"] == "pending"


class _SpySession:
    """Wraps a real session and records, in order, each SELECT (with whether it asked for a row lock) and anything else of interest."""

    def __init__(self, session, events):
        self._s, self.events = session, events

    async def execute(self, stmt, *a, **k):
        if hasattr(stmt, "_for_update_arg"):
            self.events.append("select FOR UPDATE" if stmt._for_update_arg is not None else "select")
        return await self._s.execute(stmt, *a, **k)

    def __getattr__(self, name):
        return getattr(self._s, name)


def spied(db_path, fn, events):
    return run(db_path, lambda s: fn(_SpySession(s, events)))


class TestAFreshReadUnderTheLock:
    def test_a_locking_read_sees_a_change_made_after_the_session_first_loaded_the_row(self, db_path):
        """Without populate_existing a locking SELECT returns the session's stale cached copy, so a concurrent change made in between would be lost."""
        pid = submit_playbook(db_path, person())

        async def scenario(s):
            from sqlalchemy import select

            # Something in this session still HOLDS the row (a strong reference): the ORM identity map only keeps clean objects weakly, so without this the object is garbage-collected and
            # the next read builds a fresh one and looks up to date BY ACCIDENT. With it held, a plain or FOR UPDATE select returns the stale cached copy: only populate_existing refreshes it.
            held = (await s.execute(select(CommunityCatalogItem).where(CommunityCatalogItem.item_id == pid))).scalar_one()
            before = {"install_count": held.data["install_count"]}
            await s.commit()  # (expire_on_commit is off, so the loaded copy stays cached)
            engine = create_engine(f"sqlite:///{db_path}")
            with Session(engine) as other:  # another request changes it behind this session's back
                r = other.get(CommunityCatalogItem, ("playbook", pid))
                r.data = {**r.data, "install_count": 7}
                other.commit()
            engine.dispose()
            locked = await community.PLAYBOOKS.get(s, pid, lock=True)
            assert held is not None  # keep the reference alive until after the read
            return before["install_count"], locked["install_count"]

        assert run(db_path, scenario) == (0, 7)


class TestRowLocks:
    """Read-modify-write paths must lock the row, or two concurrent requests lose an increment (the in-memory dictionaries could not have this race, the database can)."""

    def test_rating_locks_the_row(self, db_path):
        publish_plugin(db_path, person())
        run(db_path, approve("plugin", "plug-1"))
        events: list[str] = []
        spied(db_path, lambda s: community.rate_community_plugin("plug-1", community.RatingIn(score=5), current_user=person(), db=s), events)
        assert events[0] == "select FOR UPDATE"

    def test_curation_locks_the_row(self, db_path):
        rule_id = publish_detection(db_path, person())
        events: list[str] = []
        spied(db_path, lambda s: community.curate_community_detection(rule_id, community.ReviewAction(action="approve"), current_user=person(), db=s), events)
        assert events[0] == "select FOR UPDATE"

    def test_a_detection_install_locks_the_row_before_counting(self, db_path):
        rule_id = publish_detection(db_path, person())
        run(db_path, approve("detection", rule_id))
        events: list[str] = []
        spied(db_path, lambda s: community.install_community_detection(rule_id, current_user=person(), db=s), events)
        assert events[0] == "select FOR UPDATE"

    def test_a_plain_read_takes_no_lock(self, db_path):
        publish_plugin(db_path, person())
        events: list[str] = []
        spied(db_path, lambda s: community.get_community_plugin("plug-1", db=s), events)
        assert events == ["select"]

    def test_the_playbook_install_does_not_hold_a_lock_across_the_engine_call(self, db_path, monkeypatch):
        pid = submit_playbook(db_path, person())
        run(db_path, approve("playbook", pid))
        events: list[str] = []

        async def fake_proxy(method, path, **kwargs):
            events.append("ENGINE CALL")
            return {"id": "engine-pb-1"}

        monkeypatch.setattr(playbooks_api, "_proxy", fake_proxy)
        spied(db_path, lambda s: community.install_community_playbook(pid, current_user=person(), db=s), events)
        assert events == ["select", "ENGINE CALL", "select FOR UPDATE"], events  # read, slow call with no lock held, THEN lock and count (and save() issues no extra SELECT)
        assert row(db_path, "playbook", pid).data["install_count"] == 1

    def test_a_refused_playbook_install_is_not_counted(self, db_path, monkeypatch):
        pid = submit_playbook(db_path, person())
        run(db_path, approve("playbook", pid))

        async def refusing_proxy(method, path, **kwargs):
            raise HTTPException(status_code=422, detail="engine said no")

        monkeypatch.setattr(playbooks_api, "_proxy", refusing_proxy)
        with pytest.raises(HTTPException):
            run(db_path, lambda s: community.install_community_playbook(pid, current_user=person(), db=s))
        assert row(db_path, "playbook", pid).data["install_count"] == 0


def rate(db_path, who, score, plugin_id="plug-1"):
    return run(db_path, lambda s: community.rate_community_plugin(plugin_id, community.RatingIn(score=score), current_user=who, db=s))


class TestRatingsCannotBeSteered:
    """The rating is shown to every tenant and orders the marketplace. It used to take every call as a new vote (one person could repeat the call to move it anywhere) and accepted ratings for pending and rejected plugins."""

    @pytest.fixture
    def approved(self, db_path):
        submitter = person()
        publish_plugin(db_path, submitter)
        run(db_path, approve("plugin", "plug-1"))
        return submitter

    def test_rating_twice_replaces_your_own_rating_it_does_not_add_a_vote(self, db_path, approved):
        me = person()
        assert rate(db_path, me, 5) == {"rating": 5.0, "rating_count": 1}
        assert rate(db_path, me, 1) == {"rating": 1.0, "rating_count": 1}
        assert row(db_path, "plugin", "plug-1").data["ratings"] == {str(me.user_id): 1}

    def test_one_person_repeating_the_call_cannot_drag_the_average(self, db_path, approved):
        others = [person() for _ in range(3)]
        for who in others:
            rate(db_path, who, 1)
        stuffer = person()
        for _ in range(25):
            result = rate(db_path, stuffer, 5)
        assert result == {"rating": 2.0, "rating_count": 4}, "three ones and one five: (1+1+1+5)/4, however often the fifth person calls"

    def test_different_people_still_average(self, db_path, approved):
        for score in (5, 4, 3):
            result = rate(db_path, person(), score)
        assert result == {"rating": 4.0, "rating_count": 3}

    def test_a_plugin_that_is_pending_cannot_be_rated_and_nothing_is_recorded(self, db_path):
        publish_plugin(db_path, person(), plugin_id="pending-1")
        with pytest.raises(HTTPException) as refused:
            rate(db_path, person(), 5, plugin_id="pending-1")
        assert refused.value.status_code == 404
        data = row(db_path, "plugin", "pending-1").data
        assert data["rating"] == 0.0 and data["rating_count"] == 0 and "ratings" not in data

    def test_a_plugin_that_was_rejected_cannot_be_rated(self, db_path):
        publish_plugin(db_path, person(), plugin_id="rejected-1")
        run(db_path, lambda s: community.review_community_plugin("rejected-1", community.ReviewAction(action="reject", notes="no"), current_user=person(), db=s))
        with pytest.raises(HTTPException) as refused:
            rate(db_path, person(), 5, plugin_id="rejected-1")
        assert refused.value.status_code == 404

    def test_a_plugin_that_does_not_exist_is_the_same_404_as_one_that_is_not_approved(self, db_path):
        publish_plugin(db_path, person(), plugin_id="pending-2")
        statuses = []
        for plugin_id in ("pending-2", "no-such-plugin"):
            with pytest.raises(HTTPException) as refused:
                rate(db_path, person(), 5, plugin_id=plugin_id)
            statuses.append((refused.value.status_code, refused.value.detail))
        assert statuses[0] == statuses[1] == (404, "Plugin not found")

    def test_the_submitter_cannot_rate_their_own_plugin(self, db_path, approved):
        with pytest.raises(HTTPException) as refused:
            rate(db_path, approved, 5)
        assert refused.value.status_code == 403
        data = row(db_path, "plugin", "plug-1").data
        assert data["rating_count"] == 0 and "ratings" not in data

    def test_ratings_recorded_before_this_existed_stay_counted_and_a_re_rating_changes_only_the_persons_own(self, db_path, approved):
        engine = create_engine(f"sqlite:///{db_path}")
        with Session(engine) as s:
            item = s.get(CommunityCatalogItem, ("plugin", "plug-1"))
            item.data = {**item.data, "rating": 4.0, "rating_count": 2}  # two legacy votes (average 4.0), no `ratings` map
            s.commit()
        engine.dispose()
        me = person()
        assert rate(db_path, me, 5) == {"rating": 4.33, "rating_count": 3}
        assert rate(db_path, me, 1) == {"rating": 3.0, "rating_count": 3}, "(8 + 1) / 3: only their own vote moved"

    def test_the_per_person_map_is_not_shown_to_anyone(self, db_path, approved):
        rate(db_path, person(), 4)
        (plugin,) = list_plugins(db_path).items
        assert "ratings" not in plugin.model_dump() and plugin.rating == 4.0 and plugin.rating_count == 1



def _publish_raw(db_path, content):
    return run(db_path, lambda s: community.publish_detection(content=content, current_user=person(), db=s))


BAD_RULES = {
    "an empty body (safe_load gives None: this was an unhandled TypeError)": "",
    "only whitespace": "   \n",
    "YAML null": "null",
    "a bare number": "42",
    "a bare string that merely MENTIONS the field names (a substring test passed it)": "title id status description logsource detection",
    "a list": "- title\n- id\n",
    "a list of mappings": "- title: x\n  id: y\n",
    "an id that is a list": "title: t\nid: [a, b]\nstatus: s\ndescription: d\nlogsource: {category: c}\ndetection: {condition: x}\n",
    "an id that is a number": "title: t\nid: 12345\nstatus: s\ndescription: d\nlogsource: {category: c}\ndetection: {condition: x}\n",
    "an id that is blank": "title: t\nid: '  '\nstatus: s\ndescription: d\nlogsource: {category: c}\ndetection: {condition: x}\n",
    "a logsource that is a list (logsource.get raised AttributeError)": "title: t\nid: abc\nstatus: s\ndescription: d\nlogsource: [process_creation]\ndetection: {condition: x}\n",
    "a logsource that is a string": "title: t\nid: abc\nstatus: s\ndescription: d\nlogsource: windows\ndetection: {condition: x}\n",
    "a logsource that is null": "title: t\nid: abc\nstatus: s\ndescription: d\nlogsource:\ndetection: {condition: x}\n",
}


class TestPublishingARuleThatIsNotARule:
    """Found by fuzzing the OpenAPI spec against a real server: an empty submission was an unhandled TypeError (HTTP 500), and several other shapes were the same kind of crash. Every one of these must be a clear 400, and nothing may be stored."""

    @pytest.mark.parametrize("label", list(BAD_RULES))
    def test_it_is_a_400_with_a_reason_not_an_unhandled_error(self, db_path, label):
        with pytest.raises(HTTPException) as refused:
            _publish_raw(db_path, BAD_RULES[label])
        assert refused.value.status_code == 400 and refused.value.detail, label

    def test_nothing_is_stored_by_any_of_them(self, db_path):
        for content in BAD_RULES.values():
            with pytest.raises(HTTPException):
                _publish_raw(db_path, content)
        assert list_detections_count(db_path) == 0

    def test_a_valid_rule_is_still_accepted_exactly_as_before(self, db_path):
        result = _publish_raw(db_path, SIGMA.format(rule_id="valid-rule-1"))
        assert result["id"] == "valid-rule-1" and result["status"] == "pending" and result["message"] == "Detection submitted for review"
        assert list_detections_count(db_path) == 1, "positive control: the counter used by the not-stored test can see a stored rule"

    def test_a_logsource_with_extra_keys_and_a_rule_with_unusual_but_valid_optional_fields_still_work(self, db_path):
        content = "title: t\nid: ok-2\nstatus: s\ndescription: d\nlogsource: {category: c, product: p, service: svc}\ndetection: {condition: x}\ntags: [a, b]\nlevel: high\nauthor: me\n"
        assert _publish_raw(db_path, content)["id"] == "ok-2"

    def test_the_messages_say_what_is_wrong(self, db_path):
        for content, expect in (("", "mapping"), ("title: t\nid: [a]\nstatus: s\ndescription: d\nlogsource: {category: c}\ndetection: {condition: x}\n", "`id`"), ("title: t\nid: a\nstatus: s\ndescription: d\nlogsource: [x]\ndetection: {condition: x}\n", "`logsource`")):
            with pytest.raises(HTTPException) as refused:
                _publish_raw(db_path, content)
            assert expect in refused.value.detail, refused.value.detail


def list_detections_count(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            return s.query(CommunityCatalogItem).filter(CommunityCatalogItem.kind == "detection").count()
    finally:
        engine.dispose()
