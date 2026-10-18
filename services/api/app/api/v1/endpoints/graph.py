"""
Graph API endpoints: attack paths, blast radius, entity neighbors, MITRE coverage.
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Any

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from app.api.v1.deps import CurrentUser, DBSession, get_current_user, require_permission
from app.db.rls import TenantDBSession
from app.db.rls_scope import acting_as_tenant
from app.models.alert import Alert
from app.models.tenant import Tenant
from app.services import graph_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


# ─── Graph backend availability ───────────────────────────────────────────────
#
# In the public demo (and in any deployment without a Neo4j sidecar) the
# knowledge graph backend is unreachable. Rather than 503-ing the whole
# Attack Path UI in that scenario, we detect connection-class errors and fall
# back to a relational reconstruction built from the case row itself
# (alert_ids + mitre_techniques). This keeps the Attack Path tab functional
# in demos while still surfacing the rich Neo4j path when one is configured.

_GRAPH_OFFLINE_MARKERS: tuple[str, ...] = (
    "ServiceUnavailable",
    "AuthError",
    "Couldn't connect",
    "Connect call failed",
    "Connection refused",
    "Name or service not known",
    "getaddrinfo",
    "Cannot resolve address",
)


def _is_graph_unavailable(exc: BaseException) -> bool:
    """Heuristic: did the failure come from the Neo4j driver being offline?"""
    cls = type(exc).__name__
    if cls in {"ServiceUnavailable", "AuthError", "ConfigurationError"}:
        return True
    msg = str(exc)
    return any(marker in msg for marker in _GRAPH_OFFLINE_MARKERS)


async def _or_503(call: Any) -> Any:
    """Await a graph WRITE, turning "the graph database cannot be reached" into HTTP 503 instead of an unhandled error (a raw 500).

    The query routes above already answer 503 when Neo4j is down; the four upsert routes did not, so fuzzing the API with Neo4j down
    produced a 500 on each of them. A connectivity failure gets a
    generic message (the driver's own text names the internal host and port, which the caller has no need of); any OTHER exception still
    propagates, so a real bug stays a visible 500.
    """
    try:
        return await call
    except HTTPException:
        raise
    except Exception as exc:
        if _is_graph_unavailable(exc):
            logger.warning("graph write failed: the graph database is unavailable (%s)", type(exc).__name__)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The graph service is unavailable") from exc
        raise


def _query_failed(exc: BaseException) -> HTTPException:
    """The 503 for a failed graph QUERY. It used to be `detail=f"Graph query failed: {exc}"`, which put the driver's own text (the internal
    host and port, resolved addresses) in the response to
    any caller who could read the graph. The exception is logged here, in full, and the caller gets a generic message."""
    logger.warning("graph query failed (%s): %s", type(exc).__name__, exc)
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Graph query failed")


# ─── Request / Response Schemas ───────────────────────────────────────────────


class GraphNode(BaseModel):
    id: str
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str


class AttackPathResponse(BaseModel):
    case_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int
    edge_count: int


class BlastRadiusResponse(BaseModel):
    entity_id: str
    entity_type: str
    hops: int
    affected_nodes: list[GraphNode]
    total_affected: int
    type_breakdown: dict[str, int]
    blast_radius_score: float


class EntityNeighborsResponse(BaseModel):
    entity_id: str
    entity_type: str
    source: GraphNode | None
    neighbors: list[dict[str, Any]]
    neighbor_count: int = 0


class MitreCoverageItem(BaseModel):
    technique_id: str
    name: str | None
    tactic: str | None
    alert_count: int


# ── Frontend-shape coverage payload ─────────────────────────────────────────
# Matches `MitreCoverage` in apps/web/src/lib/api.ts so the analyst console's
# /api/v1/graph/mitre/coverage call hydrates without a 404 + client-side
# remap. Intensity is normalized to [0, 1] across the returned cell set.


class MitreCoverageCell(BaseModel):
    techniqueId: str
    techniqueName: str
    tactic: str
    detections: int
    alerts: int
    intensity: float


class MitreCoverageResponse(BaseModel):
    tactics: list[str]
    cells: list[MitreCoverageCell]
    generatedAt: str


class UpsertHostRequest(BaseModel):
    host_id: str
    hostname: str
    ip_address: str = ""
    os: str = ""
    criticality: str = "medium"


class UpsertUserRequest(BaseModel):
    user_id: str
    username: str
    email: str = ""
    department: str = ""
    risk_score: float = 0.0


class UpsertAlertGraphRequest(BaseModel):
    alert_id: str
    title: str
    severity: str
    mitre_techniques: list[str] = Field(default_factory=list)
    host_id: str | None = None
    user_id: str | None = None
    ioc_values: list[str] = Field(default_factory=list)


class UpsertCaseGraphRequest(BaseModel):
    case_id: str
    title: str
    severity: str
    alert_ids: list[str] = Field(default_factory=list)


# ─── Endpoints ────────────────────────────────────────────────────────────────


async def _attack_path_from_relational(
    db: Any,
    case_id: str,
    tenant_id: uuid.UUID,
) -> dict[str, Any] | None:
    """Reconstruct an attack path graph from the relational case row, ONLY if the case belongs to `tenant_id`.

    This used to look the case up by id alone, and it runs not just when Neo4j is offline but whenever the (tenant-scoped) graph returns no nodes, which is exactly what a case id from ANOTHER tenant produces: so any caller with alerts:read could read another tenant's case title, severity, MITRE techniques and alert ids, with the graph online or not.

    Used as a fallback when the Neo4j knowledge graph is unreachable so the
    Attack Path tab still renders something meaningful in demo deployments
    that don't ship a graph database. Returns ``None`` if the case can't be
    located so the caller can decide whether to 404.
    """
    row = (
        await db.execute(
            text(
                "SELECT id, title, severity, mitre_techniques, alert_ids FROM aisoc_cases WHERE id = CAST(:cid AS UUID) AND tenant_id = :tenant_id"
            ).bindparams(cid=case_id, tenant_id=tenant_id)
        )
    ).fetchone()
    if not row:
        return None

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    case_node_id = f"case:{row.id}"
    nodes.append(
        {
            "id": case_node_id,
            "label": "Case",
            "properties": {
                "title": row.title,
                "severity": row.severity,
            },
        }
    )

    # mitre_techniques may be list[str] or list[dict] depending on seed era
    techniques: list[str] = []
    for item in row.mitre_techniques or []:
        if isinstance(item, str):
            techniques.append(item)
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id")
            if tid:
                techniques.append(str(tid))

    technique_node_ids: list[str] = []
    for tid in techniques:
        nid = f"technique:{tid}"
        technique_node_ids.append(nid)
        nodes.append(
            {
                "id": nid,
                "label": "Technique",
                "properties": {"technique_id": tid},
            }
        )

    for alert_id in row.alert_ids or []:
        alert_node_id = f"alert:{alert_id}"
        nodes.append(
            {
                "id": alert_node_id,
                "label": "Alert",
                "properties": {"alert_id": str(alert_id)},
            }
        )
        edges.append({"source": case_node_id, "target": alert_node_id, "type": "INCLUDES"})
        # Best-effort attribution: each alert links to all case techniques.
        for tnid in technique_node_ids:
            edges.append({"source": alert_node_id, "target": tnid, "type": "USES_TECHNIQUE"})

    return {
        "case_id": str(row.id),
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


# ─── Overview graph ───────────────────────────────────────────────────────────
#
# GET /graph is what the Attack Graph page draws: the hosts, users and IP addresses that recent alerts touch, the ATT&CK techniques those alerts used, and which entity
# sits with which technique. It is built from the alerts themselves (the same rows the Alerts page reads), so it works with or without the Neo4j sidecar, and it covers the
# caller's own tenant and its client tenants. It never invents a node: with no alerts it returns an empty graph.

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
_ENTITY_KINDS = (("affected_hosts", "host"), ("affected_users", "user"), ("affected_ips", "ip"))
_MAX_ENTITIES_PER_KIND = 20
_MAX_TECHNIQUES = 15
_MAX_ENTITIES_PER_ALERT = 6
_OVERVIEW_WINDOW_DAYS = 30
_OVERVIEW_ALERT_CAP = 2000  # newest first, per tenant


def _technique_ids(raw: Any) -> list[str]:
    """Technique ids from an alert's mitre_techniques, which is a list of strings or of objects depending on how the alert was written."""
    out: list[str] = []
    for item in raw or []:
        tid = item if isinstance(item, str) else (item.get("id") or item.get("technique_id")) if isinstance(item, dict) else None
        if tid and str(tid).strip():
            out.append(str(tid).strip())
    return out


def _names(raw: Any) -> list[str]:
    return [str(x).strip() for x in (raw or []) if isinstance(x, str | int) and str(x).strip()]


def build_overview(alerts: list[dict[str, Any]], *, entity: str | None = None) -> dict[str, Any]:
    """The overview graph from alert rows: ``{severity, hosts, users, ips, techniques}`` each. Pure, so it is testable without a database.

    The busiest entities and techniques are kept (a cap per kind), and an edge joins an entity to a technique when an alert names both; its weight is how many alerts did.
    ``entity`` narrows the graph to alerts that name that host, user or address (compared without regard to case).
    """
    wanted = (entity or "").strip().lower()
    per_node: dict[tuple[str, str], dict[str, Any]] = {}
    pairs: dict[tuple[tuple[str, str], str], int] = {}
    together: dict[tuple[tuple[str, str], tuple[str, str]], int] = {}
    technique_counts: dict[str, int] = {}
    for a in alerts:
        severity = a.get("severity") if a.get("severity") in _SEVERITY_RANK else "info"
        entities = [(kind, name) for field, kind in _ENTITY_KINDS for name in _names(a.get(field))]
        if wanted and not any(name.lower() == wanted for _k, name in entities):
            continue
        techniques = _technique_ids(a.get("mitre_techniques"))
        # Two different kinds of entity on one alert (a host and the user on it, a host and its address) are linked: that is how a user is connected to a machine when no technique is known.
        distinct = sorted(set(entities))[:_MAX_ENTITIES_PER_ALERT]
        for i, first in enumerate(distinct):
            for second in distinct[i + 1 :]:
                if first[0] != second[0]:
                    together[(first, second)] = together.get((first, second), 0) + 1
        for key in entities:
            node = per_node.setdefault(key, {"alerts": 0, "severity": "info"})
            node["alerts"] += 1
            if _SEVERITY_RANK[severity] > _SEVERITY_RANK[node["severity"]]:
                node["severity"] = severity
            for tid in set(techniques):
                pairs[(key, tid)] = pairs.get((key, tid), 0) + 1
        for tid in set(techniques):
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

    kept: set[tuple[str, str]] = set()
    for _field, kind in _ENTITY_KINDS:
        ranked = sorted((k for k in per_node if k[0] == kind), key=lambda k: (-per_node[k]["alerts"], k[1].lower()))
        kept.update(ranked[:_MAX_ENTITIES_PER_KIND])
    top_techniques = {t for t, _n in sorted(technique_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_TECHNIQUES]}

    nodes: list[dict[str, Any]] = []
    for kind, name in sorted(kept, key=lambda k: (k[0], k[1].lower())):
        info = per_node[(kind, name)]
        nodes.append(
            {
                "id": f"{kind}:{name}",
                "label": name,
                "kind": kind,
                "riskScore": _SEVERITY_SCORE[info["severity"]],
                "severity": info["severity"],
                "attributes": {"alerts": info["alerts"]},
            }
        )
    used_techniques = {t for (key, t) in pairs if key in kept and t in top_techniques}
    for tid in sorted(used_techniques):
        nodes.append({"id": f"technique:{tid}", "label": tid, "kind": "technique", "attributes": {"alerts": technique_counts[tid]}})
    edges = [
        {"id": f"{key[0]}:{key[1]}->{tid}", "source": f"{key[0]}:{key[1]}", "target": f"technique:{tid}", "label": "alerts using technique", "weight": count}
        for (key, tid), count in sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1].lower(), kv[0][1]))
        if key in kept and tid in top_techniques
    ]
    edges += [
        {"id": f"{a[0]}:{a[1]}--{b[0]}:{b[1]}", "source": f"{a[0]}:{a[1]}", "target": f"{b[0]}:{b[1]}", "label": "seen on the same alert", "weight": count}
        for (a, b), count in sorted(together.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))
        if a in kept and b in kept
    ]
    return {"nodes": nodes, "edges": edges}


@router.get(
    "",
    summary="Overview graph: entities and ATT&CK techniques seen on recent alerts",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_overview(
    db: TenantDBSession,
    current_user: CurrentUser = Depends(get_current_user),
    entity: Annotated[str | None, Query(max_length=255, description="Only alerts that name this host, user or IP address.")] = None,
    depth: Annotated[int, Query(ge=1, le=6, description="Accepted for compatibility; the overview is always one hop (entity to technique).")] = 3,
) -> dict[str, Any]:
    """The graph the Attack Graph page draws, from the last 30 days of alerts across the caller's tenant and its client tenants (see the note above)."""
    since = datetime.now(UTC) - timedelta(days=_OVERVIEW_WINDOW_DAYS)
    clients = [row.id for row in (await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))).all()]
    rows: list[dict[str, Any]] = []
    for tenant_id in [current_user.tenant_id, *clients]:
        async with acting_as_tenant(db, tenant_id):
            result = await db.execute(
                select(Alert.severity, Alert.affected_hosts, Alert.affected_users, Alert.affected_ips, Alert.mitre_techniques)
                .where(Alert.tenant_id == tenant_id, Alert.created_at >= since)
                .order_by(Alert.created_at.desc())
                .limit(_OVERVIEW_ALERT_CAP)
            )
            rows.extend(
                {"severity": r.severity, "affected_hosts": r.affected_hosts, "affected_users": r.affected_users, "affected_ips": r.affected_ips, "mitre_techniques": r.mitre_techniques}
                for r in result.all()
            )
    graph = build_overview(rows, entity=entity)
    return {**graph, "generatedAt": datetime.now(UTC).isoformat(), "alertsConsidered": len(rows)}


@router.get(
    "/attack-path/{case_id}",
    response_model=AttackPathResponse,
    summary="Get attack path graph for a case",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_attack_path(
    case_id: str,
    db: DBSession,
    max_depth: Annotated[int, Query(ge=1, le=10)] = 6,
    current_user: CurrentUser = Depends(get_current_user),
) -> AttackPathResponse:
    """
    Traverse the knowledge graph from a Case node to reconstruct the full
    attack path: Case → Alerts → Hosts/Users → IOCs → MITRE Techniques.

    Falls back to a relational reconstruction (Case → Alerts → Techniques)
    when the Neo4j graph backend is offline so the demo Attack Path UI
    keeps working without a graph database deployed.
    """
    data: dict[str, Any] | None = None
    graph_offline = False
    try:
        data = await graph_service.get_attack_path(
            case_id=case_id,
            tenant_id=str(current_user.tenant_id),
            max_depth=max_depth,
        )
    except Exception as exc:
        if not _is_graph_unavailable(exc):
            raise _query_failed(exc) from exc
        logger.info(
            "attack-path: graph backend unavailable, using relational fallback (%s: %s)",
            type(exc).__name__,
            exc,
        )
        graph_offline = True

    if graph_offline or not data or not data.get("nodes"):
        fallback = await _attack_path_from_relational(db, case_id, current_user.tenant_id)
        if fallback is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case {case_id} not found",
            )
        if not fallback["nodes"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case {case_id} has no linked entities",
            )
        return AttackPathResponse(**fallback)

    return AttackPathResponse(**data)


@router.get(
    "/blast-radius/{entity_type}/{entity_id}",
    response_model=BlastRadiusResponse,
    summary="Compute blast radius from an entity",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_blast_radius(
    entity_type: str,
    entity_id: str,
    hops: Annotated[int, Query(ge=1, le=6)] = 3,
    current_user: CurrentUser = Depends(get_current_user),
) -> BlastRadiusResponse:
    """
    Compute the blast radius starting from a Host, User, or IOC node.
    Returns all entities reachable within `hops` and a severity score.
    """
    valid_types = {"host", "user", "ioc", "alert"}
    if entity_type.lower() not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"entity_type must be one of: {sorted(valid_types)}",
        )

    try:
        data = await graph_service.get_blast_radius(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=str(current_user.tenant_id),
            hops=hops,
        )
    except Exception as exc:
        raise _query_failed(exc) from exc

    return BlastRadiusResponse(**data)


@router.get(
    "/neighbors/{entity_type}/{entity_id}",
    response_model=EntityNeighborsResponse,
    summary="Get immediate graph neighbors of an entity",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_entity_neighbors(
    entity_type: str,
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> EntityNeighborsResponse:
    """Return all nodes directly connected (depth 1) to the specified entity."""
    try:
        data = await graph_service.get_entity_neighbors(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        raise _query_failed(exc) from exc

    return EntityNeighborsResponse(**data)


@router.get(
    "/mitre-coverage",
    response_model=list[MitreCoverageItem],
    summary="MITRE ATT&CK technique coverage for tenant",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_mitre_coverage(
    current_user: CurrentUser = Depends(get_current_user),
) -> list[MitreCoverageItem]:
    """Return MITRE ATT&CK technique coverage aggregated from all tenant alerts.

    When the Neo4j knowledge graph is unreachable (e.g. in the public demo),
    this endpoint returns an empty list rather than 503-ing, so the Coverage
    UI degrades gracefully instead of breaking the whole page.
    """
    try:
        records = await graph_service.get_mitre_coverage(
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        if _is_graph_unavailable(exc):
            logger.info(
                "MITRE coverage: graph backend unavailable, returning empty set",
                exc_info=False,
            )
            return []
        raise _query_failed(exc) from exc

    return [
        MitreCoverageItem(
            technique_id=r.get("technique_id", ""),
            name=r.get("name"),
            tactic=r.get("tactic"),
            alert_count=r.get("alert_count", 0),
        )
        for r in records
    ]


@router.get(
    "/mitre/coverage",
    response_model=MitreCoverageResponse,
    summary="MITRE ATT&CK coverage (frontend shape)",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_mitre_coverage_compat(
    db: DBSession,
    current_user: CurrentUser = Depends(get_current_user),
) -> MitreCoverageResponse:
    """Aggregated MITRE coverage in the shape the analyst console expects.

    The console's :code:`graph.getMitreCoverage()` call hits this URL and
    expects ``{ tactics, cells, generatedAt }``.  We aggregate the
    per-technique records returned by the same Neo4j-backed service used by
    ``/graph/mitre-coverage`` and degrade gracefully (empty set) when the
    knowledge graph is offline, mirroring that endpoint's behaviour.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    records: list[dict[str, Any]] = []
    try:
        records = await graph_service.get_mitre_coverage(
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        if not _is_graph_unavailable(exc):
            raise _query_failed(exc) from exc
        logger.info(
            "MITRE coverage (compat): graph backend unavailable; using alerts",
            exc_info=False,
        )

    if not records:
        # No graph (or nothing in it): fall back to the techniques the alerts themselves carry.
        from app.services.mitre_from_alerts import observed_techniques

        observed = await observed_techniques(db, current_user.tenant_id)
        records = [
            {"technique_id": tid, "name": tid, "tactic": cell["tactic"], "alert_count": cell["alerts"]}
            for tid, cell in sorted(observed.items())
        ]

    cells: list[MitreCoverageCell] = []
    tactics: set[str] = set()
    max_alerts = 1
    for r in records:
        max_alerts = max(max_alerts, int(r.get("alert_count", 0) or 0))

    for r in records:
        technique_id = r.get("technique_id") or ""
        tactic = r.get("tactic") or "unknown"
        alerts = int(r.get("alert_count", 0) or 0)
        # detections per technique aren't tracked in the graph schema yet;
        # treat coverage as a 1:1 proxy of alert evidence so the heatmap has
        # something to shade. When richer data lands, swap in a separate
        # aggregation here.
        detections = 1 if alerts > 0 else 0
        intensity = round(alerts / max_alerts, 4) if max_alerts else 0.0

        tactics.add(tactic)
        cells.append(
            MitreCoverageCell(
                techniqueId=technique_id,
                techniqueName=r.get("name") or technique_id,
                tactic=tactic,
                detections=detections,
                alerts=alerts,
                intensity=intensity,
            )
        )

    return MitreCoverageResponse(
        tactics=sorted(tactics),
        cells=cells,
        generatedAt=_dt.now(_UTC).isoformat(),
    )


# ─── Write Endpoints ──────────────────────────────────────────────────────────


@router.post(
    "/entities/host",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a Host node in the graph",
    dependencies=[Depends(require_permission("alerts:write"))],
)
async def upsert_host(
    payload: UpsertHostRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a Host node in the knowledge graph."""
    await _or_503(
        graph_service.upsert_host(
            host_id=payload.host_id,
            hostname=payload.hostname,
            tenant_id=str(current_user.tenant_id),
            ip_address=payload.ip_address,
            os=payload.os,
            criticality=payload.criticality,
        )
    )
    return {"status": "ok", "host_id": payload.host_id}


@router.post(
    "/entities/user",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a User node in the graph",
    dependencies=[Depends(require_permission("alerts:write"))],
)
async def upsert_user(
    payload: UpsertUserRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a User node in the knowledge graph."""
    await _or_503(
        graph_service.upsert_user(
            user_id=payload.user_id,
            username=payload.username,
            tenant_id=str(current_user.tenant_id),
            email=payload.email,
            department=payload.department,
            risk_score=payload.risk_score,
        )
    )
    return {"status": "ok", "user_id": payload.user_id}


@router.post(
    "/entities/alert",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert an Alert node and its relationships in the graph",
    dependencies=[Depends(require_permission("alerts:write"))],
)
async def upsert_alert_graph(
    payload: UpsertAlertGraphRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """
    Create or update an Alert node and link it to Host, User, IOC, and Technique nodes.
    Called automatically after alert creation to keep the graph in sync.
    """
    await _or_503(
        graph_service.upsert_alert_node(
            alert_id=payload.alert_id,
            tenant_id=str(current_user.tenant_id),
            title=payload.title,
            severity=payload.severity,
            mitre_techniques=payload.mitre_techniques,
            host_id=payload.host_id,
            user_id=payload.user_id,
            ioc_values=payload.ioc_values,
        )
    )
    return {"status": "ok", "alert_id": payload.alert_id}


@router.post(
    "/entities/case",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a Case node and link to alerts in the graph",
    dependencies=[Depends(require_permission("alerts:write"))],
)
async def upsert_case_graph(
    payload: UpsertCaseGraphRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a Case node and link it to Alert nodes."""
    await _or_503(
        graph_service.upsert_case_node(
            case_id=payload.case_id,
            tenant_id=str(current_user.tenant_id),
            title=payload.title,
            severity=payload.severity,
            alert_ids=payload.alert_ids,
        )
    )
    return {"status": "ok", "case_id": payload.case_id}
