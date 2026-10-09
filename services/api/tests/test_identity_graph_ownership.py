"""A tenant may only link ITS OWN identity nodes (and alerts) into edges and alert links.

Found by a two-tenant flow test of the real API: tenant B created an identity-graph edge from its own node to tenant A's node and got 201. The tenant was always stamped on the NEW row, but the nodes it points at were never checked: the database foreign key
accepts any existing node, so the edge was stored (and graph walks over edges could then cross into the other tenant), while a nonexistent id was an unhandled IntegrityError (HTTP 500). Foreign and nonexistent ids now get the SAME 404, so the endpoint cannot be used to
probe which node ids exist in other tenants. The alert-link endpoint had the same gap for both its node and its alert.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import identity_graph as ig
from app.models.identity_graph import AlertIdentityLink, IdentityEdge


def _user() -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", email="a@example.com")


def _db(*payloads):
    """Queue one payload per execute(): a list answers .scalars().all(); anything else answers .scalar_one_or_none(). Statements are recorded (SQL text and bound values)."""
    db = MagicMock()
    db.executed = []
    queue = iter(payloads)

    async def _execute(stmt, *a, **k):
        db.executed.append((" ".join(str(stmt).split()).lower(), list(stmt.compile().params.values())))
        payload = next(queue, None)
        res = MagicMock()
        res.scalars.return_value.all.return_value = payload if isinstance(payload, list) else []
        res.scalar_one_or_none.return_value = None if isinstance(payload, list) else payload
        return res

    db.execute = AsyncMock(side_effect=_execute)
    db.add, db.commit, db.refresh = MagicMock(), AsyncMock(), AsyncMock()
    return db


def _edge(src, tgt):
    return ig.EdgeCreate(source_id=src, target_id=tgt, edge_type="member_of")


@pytest.mark.asyncio
class TestCreateEdge:
    async def test_two_nodes_of_the_callers_own_are_linked(self):
        user, a, b = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([a, b])
        out = await ig.create_edge(body=_edge(a, b), db=db, current_user=user)
        db.add.assert_called_once()
        added = db.add.call_args.args[0]
        assert isinstance(added, IdentityEdge) and added.tenant_id == user.tenant_id and added.source_id == a and added.target_id == b and out is added
        db.commit.assert_awaited_once()

    async def test_a_foreign_node_is_a_404_and_nothing_is_stored(self):
        user, mine, theirs = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([mine])  # only one of the two belongs to this tenant
        with pytest.raises(HTTPException) as exc:
            await ig.create_edge(body=_edge(mine, theirs), db=db, current_user=user)
        assert exc.value.status_code == 404 and exc.value.detail == "Node not found"
        db.add.assert_not_called()
        db.commit.assert_not_awaited()

    async def test_either_end_being_foreign_is_enough_to_refuse(self):
        user, mine, theirs = _user(), uuid.uuid4(), uuid.uuid4()
        for src, tgt in ((theirs, mine), (mine, theirs), (theirs, theirs)):
            db = _db([mine] if mine in (src, tgt) else [])
            with pytest.raises(HTTPException):
                await ig.create_edge(body=_edge(src, tgt), db=db, current_user=user)
            db.add.assert_not_called()

    async def test_a_nonexistent_node_gets_the_identical_answer(self):
        """So the endpoint cannot be used to probe which node ids exist in other tenants (and it is no longer an unhandled IntegrityError)."""
        user, answers = _user(), []
        for found in ([], []):
            with pytest.raises(HTTPException) as exc:
                await ig.create_edge(body=_edge(uuid.uuid4(), uuid.uuid4()), db=_db(found), current_user=user)
            answers.append((exc.value.status_code, exc.value.detail))
        assert answers[0] == answers[1] == (404, "Node not found")

    async def test_an_edge_from_a_node_to_itself_needs_only_that_one_node(self):
        user, a = _user(), uuid.uuid4()
        db = _db([a])
        await ig.create_edge(body=_edge(a, a), db=db, current_user=user)
        db.add.assert_called_once()

    async def test_the_ownership_query_is_bound_to_the_callers_tenant_and_the_named_nodes(self):
        user, a, b = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([a, b])
        await ig.create_edge(body=_edge(a, b), db=db, current_user=user)
        sql, values = db.executed[0]
        assert "identity_nodes" in sql and "tenant_id" in sql and " in " in sql
        assert user.tenant_id in values
        flat = str(values)
        assert str(a) in flat and str(b) in flat


@pytest.mark.asyncio
class TestLinkAlertToIdentity:
    def link(self, node, alert):
        return ig.AlertLinkCreate(alert_id=alert, node_id=node, link_reason="seen on host")

    async def test_the_callers_own_node_and_alert_are_linked(self):
        user, node, alert = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([node], alert)
        out = await ig.link_alert_to_identity(body=self.link(node, alert), db=db, current_user=user)
        added = db.add.call_args.args[0]
        assert isinstance(added, AlertIdentityLink) and added.tenant_id == user.tenant_id and out is added
        db.commit.assert_awaited_once()

    async def test_a_foreign_node_is_a_404_and_the_alert_is_not_even_looked_up(self):
        user, node, alert = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([])
        with pytest.raises(HTTPException) as exc:
            await ig.link_alert_to_identity(body=self.link(node, alert), db=db, current_user=user)
        assert exc.value.status_code == 404 and exc.value.detail == "Node not found" and len(db.executed) == 1
        db.add.assert_not_called()

    async def test_a_foreign_alert_is_a_404_and_nothing_is_stored(self):
        user, node, alert = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([node], None)  # the node is the caller's; no alert of the caller's matches
        with pytest.raises(HTTPException) as exc:
            await ig.link_alert_to_identity(body=self.link(node, alert), db=db, current_user=user)
        assert exc.value.status_code == 404 and exc.value.detail == "Alert not found"
        db.add.assert_not_called()
        db.commit.assert_not_awaited()

    async def test_the_alert_lookup_is_scoped_to_the_callers_tenant(self):
        user, node, alert = _user(), uuid.uuid4(), uuid.uuid4()
        db = _db([node], alert)
        await ig.link_alert_to_identity(body=self.link(node, alert), db=db, current_user=user)
        sql, values = db.executed[1]
        assert "alerts" in sql and "tenant_id" in sql and user.tenant_id in values and alert in values
