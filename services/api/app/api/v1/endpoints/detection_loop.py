"""Closed-loop detection engineering (tier2-detection-loop).

When an analyst marks an alert as a false-positive (FP), this module:

1. Retrieves the triggering detection rule and the alert's raw evidence.
2. Invokes an LLM to draft a Sigma YAML improvement that would suppress
   the FP without widening the exclusion too broadly.
3. Creates a ``DetectionRuleProposal`` via the existing DAC lifecycle so the
   suggestion is eval-gated before promotion.
4. Returns the draft proposal ID and the diff for the analyst to review.

Endpoints
---------
* ``POST /detection-loop/suggest``            Trigger FP → Sigma draft.
* ``GET  /detection-loop/suggestions``        List LLM-drafted suggestions.
* ``GET  /detection-loop/suggestions/{id}``   Detail of one suggestion.
"""

from __future__ import annotations

import json
import textwrap
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.db.rls import TenantDBSession
from app.models.detection_suggestion import DetectionSuggestion

logger = structlog.get_logger()

MAX_LISTED = 500  # a suggestion list, not a data store: the newest N

router = APIRouter(prefix="/detection-loop", tags=["detection_rules", "detection_loop"])

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class SuggestRequest(BaseModel):
    alert_id: uuid.UUID = Field(..., description="ID of the FP-flagged alert.")
    analyst_note: str | None = Field(None, description="Free-text note explaining why this is a FP.")


class SuggestionResponse(BaseModel):
    suggestion_id: uuid.UUID
    alert_id: uuid.UUID
    base_rule_id: uuid.UUID | None
    draft_rule_name: str
    draft_sigma_yaml: str
    rationale: str
    proposal_id: uuid.UUID | None
    created_at: datetime


class SuggestionListResponse(BaseModel):
    suggestions: list[SuggestionResponse]
    total: int


# ────────────────────────────────────────────────────────────────────────────
# LLM helper
# ────────────────────────────────────────────────────────────────────────────

_SYS_PROMPT = textwrap.dedent(
    """
    You are a senior detection engineer reviewing a false-positive alert.
    The user will provide:
    - The Sigma rule that triggered the alert (YAML).
    - Key fields from the alert that fired.
    - An analyst note explaining why this is benign.

    Your task is to produce a *minimal, targeted* Sigma rule modification that
    suppresses this class of false-positive without unduly widening the exclusion.
    Prefer:
    - Adding a `filter` condition rather than removing detection logic.
    - Scoping exclusions to specific processes, users, or source paths when
      the evidence supports it.
    - Keeping the rule's ATT&CK technique tags unchanged.

    Respond in JSON only with this schema:
    {
      "rule_name": "...",        // may append '-v2' or '-fp-fix'
      "sigma_yaml": "...",       // full updated Sigma YAML
      "rationale": "..."         // ≤ 3 sentences explaining the change
    }
    """
).strip()


async def _llm_draft_sigma(
    current_sigma: str,
    alert_fields: dict[str, Any],
    analyst_note: str,
) -> dict[str, Any]:
    """Call LLM to draft a Sigma improvement. Returns parsed JSON or template."""
    api_key = getattr(settings, "OPENAI_API_KEY", None) or getattr(settings, "LLM_API_KEY", None)
    if not api_key:
        return _template_fallback(current_sigma, alert_fields, analyst_note)

    user_msg = json.dumps(
        {
            "current_sigma_rule": current_sigma,
            "alert_fields": alert_fields,
            "analyst_note": analyst_note,
        },
        indent=2,
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4o-mini",
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": _SYS_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            return json.loads(raw)
    except Exception:
        return _template_fallback(current_sigma, alert_fields, analyst_note)


def _template_fallback(current_sigma: str, alert_fields: dict[str, Any], analyst_note: str) -> dict[str, Any]:
    """Return a structured template when no LLM key is configured."""
    proc = alert_fields.get("process_name") or alert_fields.get("Image") or "UNKNOWN"
    user = alert_fields.get("user") or alert_fields.get("User") or "UNKNOWN"
    return {
        "rule_name": "fp-exclusion-draft",
        "sigma_yaml": textwrap.dedent(
            f"""\
            # AUTO-DRAFTED FP EXCLUSION — review before promoting
            # Original analyst note: {analyst_note}
            # Alert fields: {json.dumps(alert_fields, default=str)[:200]}
            filter:
              - process_name: '{proc}'
              - User: '{user}'
            condition: selection and not filter
            """
        ),
        "rationale": (
            f"Auto-generated exclusion for process '{proc}' / user '{user}'. "
            "Review and tighten before promoting. "
            "Analyst note: " + (analyst_note or "none provided")
        ),
    }


# ────────────────────────────────────────────────────────────────────────────
# In-memory store (replace with DB table in prod)
# ────────────────────────────────────────────────────────────────────────────

# Suggestions are stored in Postgres (table detection_suggestions; see migrations/058). They used to be a process-wide dict: lost on restart, and the draft proposal row did not carry enough to rebuild them.


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


def _to_response(row: DetectionSuggestion) -> SuggestionResponse:
    return SuggestionResponse(
        suggestion_id=row.id,
        alert_id=row.alert_id,
        base_rule_id=row.base_rule_id,
        draft_rule_name=row.draft_rule_name,
        draft_sigma_yaml=row.draft_sigma_yaml,
        rationale=row.rationale,
        proposal_id=row.proposal_id,
        created_at=row.created_at,
    )


@router.post(
    "/suggest",
    response_model=SuggestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Draft Sigma improvement for a FP alert",
    dependencies=[Depends(require_permission("alerts:write"))],
)
async def suggest_fp_fix(
    body: SuggestRequest,
    db: TenantDBSession,
    user: AuthUser,
) -> SuggestionResponse:
    """Retrieve the triggering rule + alert evidence, then draft a Sigma improvement.

    Tenant isolation: the alert and rule lookups are scoped to ``user.tenant_id``
    so a caller cannot pull another tenant's evidence by guessing an ``alert_id``.
    ``TenantDBSession`` also sets the Postgres RLS context for defense in depth.
    """
    # 1. Load alert — scoped to caller's tenant. A cross-tenant alert_id 404s
    # before any evidence or rule body is read.
    # `alerts` has no `evidence` column (and `aisoc_alerts`, which this used to query, was never created, so this endpoint failed on every call): the evidence is composed from the alert's own fields.
    row = await db.execute(
        text("SELECT rule_id, tenant_id, title, severity, mitre_techniques, raw_event, entities, iocs FROM alerts " "WHERE id = :aid AND tenant_id = :tenant_id").bindparams(
            aid=body.alert_id, tenant_id=user.tenant_id
        )
    )
    alert_row = row.fetchone()
    if not alert_row:
        raise HTTPException(status_code=404, detail="Alert not found")

    rule_id = alert_row.rule_id
    evidence: dict[str, Any] = {
        key: value
        for key, value in {
            "title": alert_row.title,
            "severity": alert_row.severity,
            "mitre_techniques": alert_row.mitre_techniques,
            "raw_event": alert_row.raw_event,
            "entities": alert_row.entities,
            "iocs": alert_row.iocs,
        }.items()
        if value not in (None, [], {}, "")
    }
    # Trust the caller's tenant for downstream writes — never echo a value
    # read from the database back into an authorization decision.
    tenant_id: uuid.UUID = user.tenant_id

    # 2. Load rule body if available — also tenant-scoped so an alert in tenant
    # A can never resolve a rule body owned by tenant B (e.g. via stale data).
    current_sigma = "# Rule body not found\n"
    # detection_rules (aisoc_detection_rules was never created). alerts.rule_id is free text but detection_rules.id, base_rule_id on the proposal and on the stored suggestion, and the response field are all UUIDs, so a rule id that is not one has no row to find,
    # must not reach a query as a malformed UUID, and is recorded as no base rule (rule_uuid is None) rather than failing the whole response.
    try:
        rule_uuid = uuid.UUID(str(rule_id)) if rule_id else None
    except ValueError:
        rule_uuid = None
    if rule_uuid is not None:
        rule_row = await db.execute(
            text("SELECT rule_body FROM detection_rules " "WHERE id = :rid AND tenant_id = :tenant_id").bindparams(
                rid=rule_uuid, tenant_id=user.tenant_id
            )
        )
        rule_data = rule_row.fetchone()
        if rule_data:
            current_sigma = rule_data.rule_body

    # 3. Draft via LLM
    draft = await _llm_draft_sigma(
        current_sigma=current_sigma,
        alert_fields=evidence,
        analyst_note=body.analyst_note or "",
    )

    suggestion_id = uuid.uuid4()
    now = datetime.now(UTC)

    # 4. Auto-create a DAC proposal
    proposal_id: uuid.UUID | None = None
    try:
        proposal_id = uuid.uuid4()
        async with db.begin_nested():  # SAVEPOINT: a failed proposal insert must not poison the suggestion that follows
            await db.execute(
                text(
                    """
                    INSERT INTO detection_rule_proposals
                      (id, tenant_id, base_rule_id, name, description,
                       rule_language, rule_body, category, severity, confidence,
                       status, source, created_at, updated_at)
                    VALUES
                      (:id, :tid, :rid, :name, :desc,
                       'sigma', :body, 'fp-fix', 'low', 70,
                       'draft', 'detection-loop', :now, :now)
                    """
                ).bindparams(
                    id=proposal_id,
                    tid=tenant_id,
                    rid=rule_uuid,
                    name=draft.get("rule_name", "fp-exclusion-draft"),
                    desc=draft.get("rationale", ""),
                    body=draft.get("sigma_yaml", ""),
                    now=now,
                )
            )
    except Exception:
        # This used to be silent (`proposal_id = None` and nothing else; the module had no logger). The suggestion is still returned and stored: a missing draft proposal is not fatal, but it must be visible.
        logger.warning("detection_loop.proposal_insert_failed", tenant_id=str(tenant_id), alert_id=str(body.alert_id), exc_info=True)
        proposal_id = None

    result = SuggestionResponse(
        suggestion_id=suggestion_id,
        alert_id=body.alert_id,
        base_rule_id=rule_uuid,
        draft_rule_name=draft.get("rule_name", "fp-exclusion-draft"),
        draft_sigma_yaml=draft.get("sigma_yaml", ""),
        rationale=draft.get("rationale", ""),
        proposal_id=proposal_id,
        created_at=now,
    )
    db.add(
        DetectionSuggestion(
            id=suggestion_id,
            tenant_id=tenant_id,  # the CALLER's tenant, never a value read back from the database
            created_by=user.user_id,
            alert_id=body.alert_id,
            base_rule_id=rule_uuid,
            draft_rule_name=result.draft_rule_name,
            draft_sigma_yaml=result.draft_sigma_yaml,
            rationale=result.rationale,
            proposal_id=proposal_id,
            created_at=now,
        )
    )
    await db.commit()  # one commit: the draft proposal (if it was created) and the suggestion are stored together
    return result


@router.get(
    "/suggestions",
    response_model=SuggestionListResponse,
    summary="List LLM-drafted Sigma suggestions",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def list_suggestions(user: AuthUser, db: TenantDBSession) -> SuggestionListResponse:
    """List suggestions drafted by *this* tenant only, newest first (explicit tenant filter, plus RLS in Postgres)."""
    where = DetectionSuggestion.tenant_id == user.tenant_id
    rows = (await db.execute(select(DetectionSuggestion).where(where).order_by(DetectionSuggestion.created_at.desc()).limit(MAX_LISTED))).scalars().all()
    total = (await db.execute(select(func.count()).select_from(DetectionSuggestion).where(where))).scalar_one()
    return SuggestionListResponse(suggestions=[_to_response(r) for r in rows], total=total)


@router.get(
    "/suggestions/{suggestion_id}",
    response_model=SuggestionResponse,
    summary="Get one Sigma suggestion",
    dependencies=[Depends(require_permission("alerts:read"))],
)
async def get_suggestion(
    suggestion_id: uuid.UUID,
    user: AuthUser,
    db: TenantDBSession,
) -> SuggestionResponse:
    """Return one suggestion if and only if it belongs to the caller's tenant.

    Tenant isolation: a cross-tenant lookup returns 404 (not 403) to avoid
    leaking the existence of a suggestion that belongs to another tenant.
    """
    row = (await db.execute(select(DetectionSuggestion).where(DetectionSuggestion.id == suggestion_id, DetectionSuggestion.tenant_id == user.tenant_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    return _to_response(row)
