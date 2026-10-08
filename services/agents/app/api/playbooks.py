"""
Pillar-2 Playbook REST API
===========================
Playbooks are a SHARED, READ-ONLY LIBRARY (the fixtures and canonical packs shipped with this service, visible to every tenant) plus each tenant's OWN playbooks (stored in Postgres, visible only to that
tenant). A tenant customises a library playbook by CLONING it.

Endpoints:
  GET    /api/v1/playbooks               - the library plus the caller's tenant's own playbooks (each tagged scope=library|tenant, editable)
  POST   /api/v1/playbooks               - create a playbook in the caller's tenant
  GET    /api/v1/playbooks/{id}          - get a library playbook or one of the tenant's own
  POST   /api/v1/playbooks/{id}/clone    - copy a library (or own) playbook into the tenant to customise it (starts DISABLED)
  PUT    /api/v1/playbooks/{id}          - update one of the tenant's own playbooks (library playbooks are read-only: 403, clone first)
  DELETE /api/v1/playbooks/{id}          - delete one of the tenant's own playbooks (library: 403)
  POST   /api/v1/playbooks/{id}/run      - execute a library or own playbook; the run belongs to the caller's tenant
  GET    /api/v1/playbooks/runs          - the caller's tenant's runs only
  GET    /api/v1/playbooks/runs/{run_id} - one of the caller's tenant's runs

Before this, every create/update/delete was written to ONE global index.json (visible to every tenant, lost on redeploy, and "index.json wins over fixtures": anyone able to PUT could override a shipped playbook
for EVERY tenant or delete it), and /runs listed every tenant's runs.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ValidationError

from app.core.caller import authenticated_tenant, resolve_tenant
from app.playbook.tenant_store import PlaybookLimitReached, PlaybookRepo, PlaybookStoreUnavailable, get_playbook_repo

from app.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookRun,
    PlaybookStore,
    draft_from_nl,
)

logger = logging.getLogger("aisoc.api.playbooks")
router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"])

# In-memory run store for Pillar-2 (swap for Redis/DB in production)
_runs: dict[str, PlaybookRun] = {}
# Which tenant each run belongs to (None: started with no tenant, i.e. development). Runs were global: /runs listed every tenant's runs and /runs/{id} returned any of them.
_run_owner: dict[str, str | None] = {}

LIBRARY_READONLY = "Shared library playbooks are read-only. Clone it into your tenant (POST /api/v1/playbooks/{id}/clone) to customise it."


# ---------------------------------------------------------------------------
# Request / Response helpers
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    context: dict[str, Any] = {}
    dry_run: bool = False


class DraftFromNLRequest(BaseModel):
    """T3.7 — analyst prompt to draft a playbook from."""

    prompt: str
    # When ``False`` the substrate (no-LLM) drafter is used. CI sets this
    # to ``False`` so tests are hermetic; the production default is
    # ``True`` so the LLM is consulted when configured.
    allow_llm: bool = True


# ---------------------------------------------------------------------------
# NL drafter (T3.7) — declared BEFORE /{playbook_id} so "draft-from-nl" isn't
# parsed as an id.
# ---------------------------------------------------------------------------


@router.post("/draft-from-nl", summary="Draft a playbook from natural language")
async def draft_playbook_from_nl(req: DraftFromNLRequest) -> dict:
    """Turn an analyst-authored sentence into a draft playbook.

    The returned playbook ships with ``enabled=false`` so the editor
    is the gate — a human reviews each step before the playbook is
    eligible to run.
    """

    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    if len(prompt) > 4000:
        raise HTTPException(status_code=400, detail="prompt is too long (max 4000 chars)")

    result = await draft_from_nl(prompt, allow_llm=bool(req.allow_llm))
    return result.to_dict()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def _tenant(request: Request, claimed: str | None = None) -> UUID | None:
    """The tenant this request acts for, as a UUID, or None if it has none (development, or a tenant that is not a UUID). An authenticated caller's own tenant always wins over `claimed`; `claimed` (the
    `tenant_id` query parameter) is only honoured for the API's own proxy, which has already authorised the user."""
    try:
        return UUID(resolve_tenant(claimed, authenticated_tenant(request)))
    except ValueError:
        return None


def _user_id(request: Request) -> UUID | None:
    caller = getattr(request.state, "caller", None) or {}
    try:
        return UUID(str(caller.get("user_id"))) if caller.get("kind") == "user" and caller.get("user_id") else None
    except ValueError:
        return None


def _tag(pb: Playbook, scope: str) -> dict:
    return {**pb.model_dump(), "scope": scope, "editable": scope == "tenant"}


async def _own(repo: PlaybookRepo, tenant: UUID | None, playbook_id: str) -> Playbook | None:
    if tenant is None:
        return None
    try:
        return await repo.get(tenant, playbook_id)
    except PlaybookStoreUnavailable:
        return None  # the shared library still works without a database


def _need_tenant(tenant: UUID | None) -> UUID:
    if tenant is None:
        raise HTTPException(status_code=400, detail="A tenant is required to save a playbook: sign in as a user of a tenant.")
    return tenant


def _unavailable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail=f"Custom playbooks cannot be stored right now: {exc}")


@router.get("", summary="The shared library plus this tenant's own playbooks")
async def list_playbooks(request: Request, enabled_only: bool = False, tenant_id: str | None = Query(None), repo: PlaybookRepo = Depends(get_playbook_repo)) -> list[dict]:
    items = [_tag(pb, "library") for pb in PlaybookStore.default().list(enabled_only=enabled_only)]
    tenant = _tenant(request, tenant_id)
    if tenant is not None:
        try:
            items += [_tag(pb, "tenant") for pb in await repo.list(tenant, enabled_only=enabled_only)]
        except PlaybookStoreUnavailable:
            pass  # the library is still returned
    return items


@router.post("", summary="Create a playbook in this tenant", status_code=201)
async def create_playbook(request: Request, playbook: Playbook, tenant_id: str | None = Query(None), repo: PlaybookRepo = Depends(get_playbook_repo)) -> dict:
    tenant = _need_tenant(_tenant(request, tenant_id))
    try:
        # A fresh id is always assigned and provenance cannot be claimed: cloned_from is only ever set by /clone.
        created = await repo.create(tenant, playbook.model_copy(update={"cloned_from": None}), created_by=_user_id(request))
    except PlaybookLimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PlaybookStoreUnavailable as exc:
        raise _unavailable(exc) from exc
    return _tag(created, "tenant")


def _runs_visible_to(request: Request, claimed: str | None) -> str | None:
    """The tenant whose runs the caller may see, or None for an unscoped caller (development / the API's own proxy without a tenant)."""
    authenticated = authenticated_tenant(request)
    return authenticated if authenticated is not None else (claimed or None)


@router.get("/runs", summary="List this tenant's recent playbook runs")
async def list_runs(request: Request, limit: int = 50, tenant_id: str | None = Query(None)) -> list[dict]:
    scope = _runs_visible_to(request, tenant_id)
    mine = [r for rid, r in _runs.items() if scope is None or _run_owner.get(rid) == scope]
    recent = sorted(mine, key=lambda r: r.started_at or "", reverse=True)[:limit]
    return [r.to_dict() for r in recent]


@router.get("/runs/{run_id}", summary="Get one of this tenant's playbook runs")
async def get_run(run_id: str, request: Request, tenant_id: str | None = Query(None)) -> dict:
    pr = _runs.get(run_id)
    scope = _runs_visible_to(request, tenant_id)
    # A run that is another tenant's (or has no recorded owner) is the SAME 404 as no such run: nothing leaks about which ids exist.
    if not pr or (scope is not None and _run_owner.get(run_id) != scope):
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return pr.to_dict()


@router.get("/{playbook_id}", summary="Get a library playbook or one of this tenant's own")
async def get_playbook(playbook_id: str, request: Request, tenant_id: str | None = Query(None), repo: PlaybookRepo = Depends(get_playbook_repo)) -> dict:
    mine = await _own(repo, _tenant(request, tenant_id), playbook_id)
    if mine is not None:
        return _tag(mine, "tenant")
    library = PlaybookStore.default().get(playbook_id)
    if library is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _tag(library, "library")


class CloneRequest(BaseModel):
    name: str | None = None


@router.post("/{playbook_id}/clone", summary="Copy a library (or own) playbook into this tenant to customise it", status_code=201)
async def clone_playbook(
    playbook_id: str,
    request: Request,
    body: CloneRequest | None = None,
    tenant_id: str | None = Query(None),
    repo: PlaybookRepo = Depends(get_playbook_repo),
) -> dict:
    tenant = _need_tenant(_tenant(request, tenant_id))
    source = await _own(repo, tenant, playbook_id) or PlaybookStore.default().get(playbook_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    name = ((body.name if body and body.name else None) or f"{source.name} (custom)").strip()[:300]
    # The copy starts DISABLED: it is a response playbook the tenant has not reviewed yet, and enabling it is a deliberate act (after editing it). It records where it came from.
    copy = source.model_copy(deep=True, update={"name": name, "cloned_from": source.id, "enabled": False, "author": "Tenant custom"})
    try:
        created = await repo.create(tenant, copy, created_by=_user_id(request))
    except PlaybookLimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PlaybookStoreUnavailable as exc:
        raise _unavailable(exc) from exc
    return _tag(created, "tenant")


@router.put("/{playbook_id}", summary="Update one of this tenant's own playbooks")
async def update_playbook(playbook_id: str, data: dict[str, Any], request: Request, tenant_id: str | None = Query(None), repo: PlaybookRepo = Depends(get_playbook_repo)) -> dict:
    tenant = _tenant(request, tenant_id)
    if await _own(repo, tenant, playbook_id) is not None:
        try:
            updated = await repo.update(_need_tenant(tenant), playbook_id, data)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=json.loads(exc.json())) from exc
        except PlaybookStoreUnavailable as exc:
            raise _unavailable(exc) from exc
        if updated is None:
            raise HTTPException(status_code=404, detail="Playbook not found")
        return _tag(updated, "tenant")
    if PlaybookStore.default().get(playbook_id) is not None:
        raise HTTPException(status_code=403, detail=LIBRARY_READONLY)
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.delete("/{playbook_id}", summary="Delete one of this tenant's own playbooks", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str, request: Request, tenant_id: str | None = Query(None), repo: PlaybookRepo = Depends(get_playbook_repo)) -> None:
    tenant = _tenant(request, tenant_id)
    if await _own(repo, tenant, playbook_id) is not None:
        try:
            if await repo.delete(_need_tenant(tenant), playbook_id):
                return
        except PlaybookStoreUnavailable as exc:
            raise _unavailable(exc) from exc
        raise HTTPException(status_code=404, detail="Playbook not found")
    if PlaybookStore.default().get(playbook_id) is not None:
        raise HTTPException(status_code=403, detail=LIBRARY_READONLY)
    raise HTTPException(status_code=404, detail="Playbook not found")


async def _execute(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_holder: list) -> None:
    """Background task: run the playbook and store the result."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    _runs[pr.run_id] = pr
    run_holder.append(pr.run_id)


@router.post("/{playbook_id}/run", summary="Execute a library or own playbook", status_code=202)
async def run_playbook(
    playbook_id: str,
    body: RunRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    tenant_id: str | None = Query(None),
    repo: PlaybookRepo = Depends(get_playbook_repo),
) -> dict:
    tenant = _tenant(request, tenant_id)
    pb = await _own(repo, tenant, playbook_id) or PlaybookStore.default().get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # The run's context names the tenant it acts for: the AUTHENTICATED tenant, never one the client put in `context`.
    context = {**body.context, "tenant_id": str(tenant)} if tenant is not None else dict(body.context)

    from app.playbook.engine import PlaybookRun as _PR
    from app.playbook.engine import RunStatus as _RS

    placeholder = _PR(pb, context)
    placeholder.status = _RS.PENDING
    _runs[placeholder.run_id] = placeholder
    _run_owner[placeholder.run_id] = str(tenant) if tenant is not None else None

    background_tasks.add_task(_execute_and_update, pb, context, body.dry_run, placeholder.run_id)

    return {
        "run_id": placeholder.run_id,
        "playbook_id": playbook_id,
        "status": "pending",
        "message": f"Playbook execution started. Poll GET /api/v1/playbooks/runs/{placeholder.run_id}",
    }


async def _execute_and_update(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_id: str) -> None:
    """Background task: overwrite placeholder with real run."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    # Keep the placeholder's run id so pollers (and the owner record) stay valid.
    pr.run_id = run_id
    _runs[run_id] = pr
