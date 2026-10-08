"""
Community ecosystem endpoints — plugin publishing, reviews, and detection catalog.

POST   /community/plugins/publish           – submit plugin tarball (signed)
GET    /community/plugins                   – browse community plugins
GET    /community/plugins/{id}              – get plugin detail + versions
POST   /community/plugins/{id}/install      – install from community to instance
POST   /community/plugins/{id}/rate         – rate a community plugin
PUT    /community/plugins/{id}/review       – admin: approve/reject submission

POST   /community/detections/publish        – submit Sigma detection rule
GET    /community/detections                – paginated Sigma rule catalog
GET    /community/detections/{id}           – get rule detail
POST   /community/detections/{id}/install   – install rule to tenant detection set

POST   /community/playbooks/submit          – submit a playbook
GET    /community/playbooks                 – browse community playbooks
POST   /community/playbooks/{id}/install    – install playbook
PUT    /community/playbooks/{id}/curate     – admin: approve/reject playbook
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, CurrentUser, DBSession, get_db, require_permission
from app.services.community_catalog import CatalogStore, ItemExists
from app.db.rls import TenantDBSession
from app.core.security import verify_ed25519_signature

router = APIRouter(prefix="/community", tags=["community"])

# -- Community catalog (database: table community_catalog_items; see app/services/community_catalog.py) --

PLUGINS = CatalogStore("plugin")
DETECTIONS = CatalogStore("detection")
PLAYBOOKS = CatalogStore("playbook")

# ── Schemas ───────────────────────────────────────────────────────────────────


class PublishStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class CommunityPluginOut(BaseModel):
    id: str
    name: str
    version: str
    plugin_type: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    rating: float = 0.0
    rating_count: int = 0
    verified: bool = False
    submitted_at: str
    approved_at: str | None = None


class CommunityPluginListOut(BaseModel):
    total: int
    items: list[CommunityPluginOut]


class ReviewAction(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")
    notes: str | None = None


class RatingIn(BaseModel):
    score: int = Field(..., ge=1, le=5)
    comment: str | None = None


class CommunityDetectionOut(BaseModel):
    id: str
    title: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    logsource: dict[str, Any] = {}
    submitted_at: str
    content: str | None = None


class CommunityPlaybookOut(BaseModel):
    id: str
    name: str
    description: str
    author: str
    tags: list[str] = []
    status: PublishStatus = PublishStatus.PENDING
    install_count: int = 0
    submitted_at: str
    definition: dict[str, Any] | None = None


# ── Plugin endpoints ──────────────────────────────────────────────────────────


@router.post("/plugins/publish", status_code=201)
async def publish_plugin(
    request: Request,
    current_user: AuthUser,
    db: TenantDBSession,
) -> dict[str, Any]:
    """Submit a signed plugin tarball for community review."""
    sig_b64 = request.headers.get("X-Plugin-Signature")
    manifest_json = request.headers.get("X-Plugin-Manifest")

    if not sig_b64 or not manifest_json:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Plugin-Signature or X-Plugin-Manifest header",
        )

    tarball = await request.body()
    if not tarball:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty body")

    try:
        manifest = json.loads(manifest_json)
        signature = base64.b64decode(sig_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid signature or manifest: {exc}") from exc

    # Signature verification — allow submission without registered key (marks as unverified)
    verified = False
    registered_pub_key = await _get_registered_pub_key(str(current_user.user_id), db)
    if registered_pub_key:
        try:
            verify_ed25519_signature(registered_pub_key, tarball, signature)
            verified = True
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Ed25519 signature",
            ) from exc

    plugin_id = manifest.get("id", str(uuid.uuid4()))
    entry = {
        "id": plugin_id,
        "name": manifest.get("name", plugin_id),
        "version": manifest.get("version", "0.0.1"),
        "plugin_type": manifest.get("plugin_type", "enricher"),
        "description": manifest.get("description", ""),
        "author": manifest.get("author", current_user.email),
        "tags": manifest.get("tags", []),
        "status": PublishStatus.PENDING,
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "verified": verified,
        "submitted_by": str(current_user.user_id),
        "submitted_at": datetime.now(UTC).isoformat(),
        "approved_at": None,
        # Only the SHA-256 is recorded. The package bytes used to be kept in process memory under "_tarball" (never served, never used, lost on restart) and are not kept at all now:
        # persisting arbitrary-size binaries is a separate decision, and installing community plugins is not implemented.
        "tarball_sha256": hashlib.sha256(tarball).hexdigest(),
    }
    # Never replace an existing entry: resubmitting an id used to overwrite it, so anyone could replace an existing plugin's entry (including an approved one).
    try:
        await PLUGINS.create(db, plugin_id, entry, submitter_tenant_id=current_user.tenant_id)
    except ItemExists as exc:
        raise HTTPException(status_code=409, detail=f"A community plugin with id {plugin_id} already exists") from exc

    return {"id": plugin_id, "status": "pending", "message": "Plugin submitted for review"}


@router.get("/plugins", response_model=CommunityPluginListOut)
async def list_community_plugins(
    status_filter: str | None = Query(None, alias="status"),
    plugin_type: str | None = Query(None),
    tags: str | None = Query(None, description="Comma-separated tags"),
    sort: str = Query("install_count", pattern="^(install_count|rating|submitted_at|name)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> CommunityPluginListOut:
    """Browse approved community plugins."""
    items = await PLUGINS.list(db)

    # Filter
    if status_filter:
        items = [p for p in items if p["status"] == status_filter]
    else:
        items = [p for p in items if p["status"] == PublishStatus.APPROVED]
    if plugin_type:
        items = [p for p in items if p["plugin_type"] == plugin_type]
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]
        items = [p for p in items if any(t in p.get("tags", []) for t in tag_list)]

    # Sort
    reverse = order == "desc"
    items.sort(key=lambda p: p.get(sort, 0), reverse=reverse)

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return CommunityPluginListOut(
        total=total,
        items=[CommunityPluginOut(**p) for p in page_items],
    )


@router.get("/plugins/{plugin_id}", response_model=CommunityPluginOut)
async def get_community_plugin(plugin_id: str, db: AsyncSession = Depends(get_db)) -> CommunityPluginOut:
    """Get community plugin detail."""
    p = await PLUGINS.get(db, plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return CommunityPluginOut(**p)


@router.post("/plugins/{plugin_id}/install", dependencies=[Depends(require_permission("settings:write"))])
async def install_community_plugin(
    plugin_id: str,
    current_user: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Install a community plugin to the current instance."""
    p = await PLUGINS.get(db, plugin_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")
    if p["status"] != PublishStatus.APPROVED:
        raise HTTPException(status_code=400, detail="Plugin is not approved for installation")

    # Publishing a plugin stores only the SHA-256 of the submitted package, never the package, so there is nothing here to install. This used to bump a counter and
    # answer "installed successfully".
    raise HTTPException(
        status_code=501,
        detail="Community plugins cannot be installed yet: only the submitted package's SHA-256 is recorded, not the package itself. Plugins are installed by an administrator.",
    )


@router.post("/plugins/{plugin_id}/rate")
async def rate_community_plugin(
    plugin_id: str,
    rating: RatingIn,
    current_user: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Rate a community plugin."""
    p = await PLUGINS.get(db, plugin_id, lock=True)  # read-modify-write: lock the row so two ratings cannot both read the same average
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")

    count = p["rating_count"]
    current_rating = p["rating"]
    new_rating = (current_rating * count + rating.score) / (count + 1)
    p["rating"] = round(new_rating, 2)
    p["rating_count"] = count + 1
    await PLUGINS.save(db, plugin_id, p)

    return {"rating": p["rating"], "rating_count": p["rating_count"]}


@router.put("/plugins/{plugin_id}/review")
async def review_community_plugin(
    plugin_id: str,
    review: ReviewAction,
    current_user: Annotated[CurrentUser, Depends(require_permission("plugins:admin"))],
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Admin: approve or reject a plugin submission."""
    p = await PLUGINS.get(db, plugin_id, lock=True)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")

    if review.action == "approve":
        p["status"] = PublishStatus.APPROVED
        p["approved_at"] = datetime.now(UTC).isoformat()
    else:
        p["status"] = PublishStatus.REJECTED
        p["review_notes"] = review.notes

    await PLUGINS.save(db, plugin_id, p)
    return {"id": plugin_id, "status": p["status"]}


# ── Detection endpoints ───────────────────────────────────────────────────────


@router.post("/detections/publish", status_code=201, dependencies=[Depends(require_permission("rules:write"))])
async def publish_detection(
    content: str = Body(..., media_type="text/plain"),
    current_user: AuthUser = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Submit a Sigma detection rule for community review."""
    import yaml as _yaml

    try:
        rule = _yaml.safe_load(content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc

    required = ["title", "id", "status", "description", "logsource", "detection"]
    missing = [f for f in required if f not in rule]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required Sigma fields: {missing}")

    detection_id = rule.get("id", str(uuid.uuid4()))
    if await DETECTIONS.get(db, detection_id) is not None:
        # Never replace an existing entry: with auto-approval, anyone could overwrite an approved rule by re-submitting its id.
        raise HTTPException(status_code=409, detail=f"A community detection with id {detection_id} already exists")
    logsource = rule.get("logsource", {})
    entry = {
        "id": detection_id,
        "name": rule.get("title", detection_id),
        "description": rule.get("description", ""),
        "author": rule.get("author", ""),
        "tags": rule.get("tags", []),
        "logsource_category": logsource.get("category", ""),
        "logsource_product": logsource.get("product", ""),
        "level": rule.get("level", "medium"),
        "status": PublishStatus.PENDING,  # submissions are reviewed before anyone can see or install them
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "submitted_at": datetime.now(UTC).isoformat(),
        "sigma_yaml": content,
    }
    try:
        await DETECTIONS.create(db, detection_id, entry, submitter_tenant_id=current_user.tenant_id)
    except ItemExists as exc:  # lost a race with a concurrent submission of the same id
        raise HTTPException(status_code=409, detail=f"A community detection with id {detection_id} already exists") from exc

    return {"id": detection_id, "status": entry["status"], "message": "Detection submitted for review"}


@router.get("/detections")
async def list_community_detections(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
    logsource_category: str | None = Query(None),
    logsource_product: str | None = Query(None),
    level: str | None = Query(None),
    sort_by: str = Query("install_count", pattern="^(install_count|rating|name)$"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Browse community Sigma detection rules with pagination and filtering."""
    items = await DETECTIONS.list(db)

    # filter by status: only approved submissions are shown
    items = [d for d in items if d["status"] in (PublishStatus.APPROVED, "approved")]

    if search:
        q = search.lower()
        items = [
            d
            for d in items
            if q in d.get("name", "").lower() or q in d.get("description", "").lower() or any(q in t.lower() for t in d.get("tags", []))
        ]
    if logsource_category:
        items = [d for d in items if d.get("logsource_category") == logsource_category]
    if logsource_product:
        items = [d for d in items if d.get("logsource_product") == logsource_product]
    if level:
        items = [d for d in items if d.get("level") == level]

    # Sort
    if sort_by == "name":
        items.sort(key=lambda d: d.get("name", "").lower())
    else:
        items.sort(key=lambda d: d.get(sort_by, 0), reverse=True)

    total = len(items)
    start = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items[start : start + page_size],
    }


@router.get("/detections/{detection_id}")
async def get_community_detection(detection_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Get Sigma rule detail including full YAML content (sigma_yaml field)."""
    d = await DETECTIONS.get(db, detection_id)
    if not d or d["status"] != PublishStatus.APPROVED:
        # An unreviewed (or rejected) submission is not visible to other users.
        raise HTTPException(status_code=404, detail="Detection not found")
    return d


@router.post("/detections/{detection_id}/install", dependencies=[Depends(require_permission("rules:write"))])
async def install_community_detection(
    detection_id: str,
    current_user: AuthUser,
    db: DBSession,
) -> dict[str, str]:
    """Install a community detection rule to the tenant."""
    d = await DETECTIONS.get(db, detection_id, lock=True)  # the install count is read-modify-write
    if not d:
        raise HTTPException(status_code=404, detail="Detection not found")
    if d["status"] != PublishStatus.APPROVED:
        raise HTTPException(status_code=400, detail="Detection is not approved for installation")
    # Installing creates a real rule in THIS tenant, in "testing" status (the model default), so it does not fire until someone promotes it. This used to only
    # bump a counter (after a KeyError on d["title"], which never existed: entries store the title under "name") and report "installed".
    from sqlalchemy import select

    from app.models.detection_rule import DetectionRule

    already = await db.execute(
        select(DetectionRule.id).where(
            DetectionRule.tenant_id == current_user.tenant_id,
            DetectionRule.name == d["name"],
            DetectionRule.rule_body == d["sigma_yaml"],
        )
    )
    if already.first() is not None:
        raise HTTPException(status_code=409, detail="This detection is already installed")
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=d["name"],
        description=d["description"] or None,
        rule_language="sigma",
        rule_body=d["sigma_yaml"],
        category=d.get("logsource_category") or "community",
        severity=_rule_severity(d.get("level")),
        tags=list(d.get("tags") or []),
        provenance={"source": "community", "community_detection_id": detection_id, "author": d.get("author", "")},
        created_by_id=current_user.user_id,
    )
    db.add(rule)
    d["install_count"] += 1
    await DETECTIONS.save(db, detection_id, d, commit=False)
    await db.commit()  # the rule and the count are committed together
    await db.refresh(rule)
    return {
        "message": f"Detection {detection_id} installed as rule {rule.id} in testing status; it does not fire until you promote it",
        "title": d["name"],
        "rule_id": str(rule.id),
    }


# ── Playbook endpoints ────────────────────────────────────────────────────────


@router.put("/detections/{detection_id}/curate")
async def curate_community_detection(
    detection_id: str,
    review: ReviewAction,
    current_user: Annotated[CurrentUser, Depends(require_permission("rules:admin"))],
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Admin: approve or reject a detection submission."""
    d = await DETECTIONS.get(db, detection_id, lock=True)
    if not d:
        raise HTTPException(status_code=404, detail="Detection not found")

    if review.action == "approve":
        d["status"] = PublishStatus.APPROVED
    else:
        d["status"] = PublishStatus.REJECTED
        d["review_notes"] = review.notes

    await DETECTIONS.save(db, detection_id, d)
    return {"id": detection_id, "status": d["status"]}


@router.post("/playbooks/submit", status_code=201, dependencies=[Depends(require_permission("playbooks:write"))])
async def submit_playbook(
    definition: dict[str, Any] = Body(...),
    current_user: AuthUser = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Submit a community playbook."""
    name = definition.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="Playbook must have a name")

    playbook_id = str(uuid.uuid4())
    entry = {
        "id": playbook_id,
        "name": name,
        "description": definition.get("description", ""),
        "author": definition.get("author", ""),
        "tags": definition.get("tags", []),
        "status": PublishStatus.PENDING,  # submissions are reviewed before anyone can see or install them
        "install_count": 0,
        "rating": 0.0,
        "rating_count": 0,
        "submitted_at": datetime.now(UTC).isoformat(),
        "definition": definition,
    }
    await PLAYBOOKS.create(db, playbook_id, entry, submitter_tenant_id=current_user.tenant_id)

    return {"id": playbook_id, "status": entry["status"], "message": "Playbook submitted for review"}


@router.get("/playbooks")
async def list_community_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
    sort_by: str = Query("install_count", pattern="^(install_count|rating|name)$"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Browse approved community playbooks with optional search and sort."""
    items = [p for p in await PLAYBOOKS.list(db) if p["status"] in (PublishStatus.APPROVED, "approved")]

    if search:
        q = search.lower()
        items = [
            p
            for p in items
            if q in p.get("name", "").lower() or q in p.get("description", "").lower() or any(q in t.lower() for t in p.get("tags", []))
        ]

    if sort_by == "name":
        items.sort(key=lambda p: p.get("name", "").lower())
    else:
        items.sort(key=lambda p: p.get(sort_by, 0), reverse=True)

    total = len(items)
    start = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items[start : start + page_size],
    }


@router.post("/playbooks/{playbook_id}/install", dependencies=[Depends(require_permission("playbooks:write"))])
async def install_community_playbook(
    playbook_id: str,
    current_user: AuthUser,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Install a community playbook to the tenant."""
    p = await PLAYBOOKS.get(db, playbook_id)
    if not p:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if p["status"] != PublishStatus.APPROVED:
        raise HTTPException(status_code=400, detail="Playbook is not approved for installation")
    # Installing creates the playbook in the engine, DISABLED, through the same proxy the API's own playbook creation uses; if the engine refuses it, the install
    # fails with that error (and is not counted). It used to only bump a counter and report "installed".
    from app.api.v1.endpoints import playbooks as playbooks_api

    # The playbook is created in the INSTALLING tenant's own playbooks (disabled until they enable it). The internal call carries no tenant of its own, so it must be named: without it the agents service has
    # nowhere to put the playbook (playbooks are a shared read-only library plus each tenant's own).
    created = await playbooks_api._proxy("POST", "", json={**p["definition"], "enabled": False}, params={"tenant_id": str(current_user.tenant_id)})
    # Re-read WITH the row lock only now, after the (slow) engine call, so the lock is never held across a network round trip.
    p = await PLAYBOOKS.get(db, playbook_id, lock=True) or p
    p["install_count"] += 1
    await PLAYBOOKS.save(db, playbook_id, p)
    new_id = str(created.get("id", "")) if isinstance(created, dict) else ""
    return {
        "message": f"Playbook {playbook_id} installed (disabled until you enable it)",
        "name": p["name"],
        "playbook_id": new_id,
    }


@router.put("/playbooks/{playbook_id}/curate")
async def curate_community_playbook(
    playbook_id: str,
    review: ReviewAction,
    current_user: Annotated[CurrentUser, Depends(require_permission("playbooks:admin"))],
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Admin: approve or reject a playbook submission."""
    p = await PLAYBOOKS.get(db, playbook_id, lock=True)
    if not p:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if review.action == "approve":
        p["status"] = PublishStatus.APPROVED
    else:
        p["status"] = PublishStatus.REJECTED
        p["review_notes"] = review.notes

    await PLAYBOOKS.save(db, playbook_id, p)
    return {"id": playbook_id, "status": p["status"]}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _rule_severity(level: Any) -> str:
    """Map a Sigma `level` to the detection rule severities (informational becomes info; anything unknown is medium)."""
    value = str(level or "medium").lower()
    if value == "informational":
        return "info"
    return value if value in {"low", "medium", "high", "critical"} else "medium"


async def _get_registered_pub_key(user_id: str, db: Any) -> bytes | None:
    """The author's registered Ed25519 plugin-signing key, if there is one. THERE IS NOT YET A REGISTRY, so this is always None and every submission is recorded as unverified.

    This used to import `Responder` from app.models.responder, a class that does not exist (the only public_key in the codebase belongs to passkeys, WebAuthn credentials, which cannot
    verify an Ed25519 package signature), and the import sat outside the try block: publishing a plugin raised ImportError (HTTP 500) every time, so it has never worked.
    """
    return None