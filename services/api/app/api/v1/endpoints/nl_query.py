"""Natural-language query → multi-dialect execution (Stage 2 #16).

Accepts a plain-English security question, translates it to ES|QL, SPL, and
KQL via the deterministic translator in :mod:`services.agents.app.nl_query`,
optionally enhances the translation with an LLM (when one is configured and
the air-gap policy allows the call), validates every emitted query against
the dialect grammar, and finally executes the ES|QL variant against a
connected Elasticsearch cluster.

The previous implementation emitted ``// TODO: translate → <question>``
fallbacks whenever no LLM was available. Stage 2 #16 removes that pattern
entirely: the deterministic translator always produces a syntactically valid
query, scored against the eval set in
``services/agents/tests/eval_data/nl_query_eval.json`` to guarantee
≥ 85% syntactic validity and ≥ 70% semantic match.

Endpoints
---------
* ``POST /nl-query/translate``      Translate NL → ES|QL / SPL / KQL.
* ``POST /nl-query/execute``        Translate + execute against Elasticsearch.
"""

from __future__ import annotations

import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field, field_validator

from app.api.v1.deps import AuthUser, require_permission
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings
from app.services.esql_runner import (
    ESQLExecutionError,
    ESQLNotConfigured,
    resolve_es_credentials,
    run_esql_query,
)

if TYPE_CHECKING:
    # Static-only re-export so type checkers can see the dataclass fields and
    # function signatures of the translator. At runtime we load the module
    # dynamically (see ``_load_nl_query_module`` below) to avoid colliding
    # with the API service's own ``app`` package.
    from services.agents.app.nl_query import (  # noqa: F401
        GrammarError,
        NLQuery,
        TranslatedQuery,
        enhance_with_llm,
    )
    from services.agents.app.nl_query import translate as deterministic_translate  # noqa: F401

# ---------------------------------------------------------------------------
# Bootstrap import path for ``services/agents/app/nl_query``.
#
# The translator is owned by ``services/agents`` so that the eval harness, the
# agents themselves, and the API can all share the same code path. We load it
# via ``importlib`` under a unique module name (``aisoc_agents_nl_query``) so
# it does not collide with the API service's own ``app`` package — both
# services define their own ``app/__init__.py`` regular package and Python's
# importer will not merge them.
# ---------------------------------------------------------------------------


def _candidate_nl_query_dirs() -> list[Path]:
    """Return ordered list of directories that may contain the nl_query module.

    The first entry is the in-tree vendored copy under
    ``services/api/app/_vendor/nl_query/`` — this is what ships inside the
    ``aisoc-api`` Docker image. The second entry is the source-of-truth tree
    at ``services/agents/app/nl_query/``, used during local development when
    the API runs outside of Docker.
    """
    here = Path(__file__).resolve()
    candidates: list[Path] = []

    # 1) Vendored copy — same Python package as this endpoint, so it lives at
    #    ``<api-app-root>/_vendor/nl_query/``. ``parents[3]`` resolves to the
    #    ``app`` directory: endpoints → v1 → api → app.
    try:
        api_app_root = here.parents[3]
        vendored = api_app_root / "_vendor" / "nl_query"
        if vendored.joinpath("__init__.py").is_file():
            candidates.append(vendored)
    except IndexError:  # pragma: no cover - defensive
        pass

    # 2) Source-of-truth tree — walk up the repo until we find it.
    for ancestor in here.parents:
        source = ancestor / "services" / "agents" / "app" / "nl_query"
        if source.joinpath("__init__.py").is_file():
            candidates.append(source)
            break

    return candidates


def _load_nl_query_module():
    """Load the nl_query translator under a collision-free module name.

    Prefers the in-tree vendored copy (so the module is available inside the
    Dockerized ``aisoc-api`` service whose build context excludes
    ``services/agents``) and falls back to the source-of-truth tree at
    ``services/agents/app/nl_query/`` for local non-Docker development.
    """
    import importlib.util

    package_name = "aisoc_agents_nl_query"
    if package_name in sys.modules:
        return sys.modules[package_name]

    candidates = _candidate_nl_query_dirs()
    if not candidates:
        raise ImportError(
            "NL query module not found — expected either "
            "services/api/app/_vendor/nl_query/ (vendored) or "
            "services/agents/app/nl_query/ (source)."
        )

    nl_query_dir = candidates[0]
    init_file = nl_query_dir / "__init__.py"

    spec = importlib.util.spec_from_file_location(
        package_name,
        init_file,
        submodule_search_locations=[str(nl_query_dir)],
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"Could not build spec for {init_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


_nl_query = _load_nl_query_module()
if not TYPE_CHECKING:
    GrammarError = _nl_query.GrammarError
    NLQuery = _nl_query.NLQuery
    TranslatedQuery = _nl_query.TranslatedQuery
    enhance_with_llm = _nl_query.enhance_with_llm
    deterministic_translate = _nl_query.translate

router = APIRouter(prefix="/nl-query", tags=["nl_query"])


# --- What a query may read ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# The caller's index_pattern was spliced VERBATIM into the generated `FROM ...` line of an ES|QL query that /execute runs with the SERVER's Elasticsearch credentials, and the vendored grammar check accepts
# every one of these (shown by running it): `FROM *`, `FROM .security-*,.kibana*` (internal indices), and injected pipeline commands (`logs-* | EVAL ... | DROP message | LIMIT 5 //`, whose `//` also comments out the translator's own LIMIT).
# A single Elasticsearch shared by tenants made that a cross-tenant read; any Elasticsearch made it a read of whatever the server's key can see. When an LLM key is configured the LLM writes the query, steered by the user's question, so the
# field alone is not enough: the final query's source clause is checked too, whoever produced it.
_INDEX_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._*-]{2,99}$")
_MAX_INDEX_TOKENS = 10
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@-]{0,99}$")
# `FROM <sources> [METADATA ...]` at the very start, ended by a newline, a pipe or the end of the query.
_SOURCE_HEAD_RE = re.compile(r"^(?P<head>\s*FROM\s+(?P<src>[^\s|,]+(?:\s*,\s*[^\s|,]+)*)(?P<meta>\s+METADATA\s+[A-Za-z0-9_@.,\s]+?)?)[ \t]*(?=\n|\||$)", re.IGNORECASE)


class QueryScopeError(ValueError):
    """The query reads something the caller may not ask for."""


def validate_index_pattern(value: str) -> str:
    """Comma-separated index names: lowercase letters, digits, `.`, `_`, `-` and `*`; each starting with a letter or digit (so never a hidden/system index, which starts with `.`) and with at least three literal characters before any `*` (so never `*`).
    No whitespace, newline, pipe or comment character can get through, so the value cannot do anything but name indices."""
    tokens = value.split(",")
    if not value or len(tokens) > _MAX_INDEX_TOKENS:
        raise QueryScopeError(f"index_pattern must name between 1 and {_MAX_INDEX_TOKENS} indices")
    for token in tokens:
        if not _INDEX_TOKEN_RE.match(token) or len(token.split("*")[0]) < 3:
            raise QueryScopeError(f"index pattern {token[:40]!r} is not allowed: use lowercase names such as 'logs-*', with at least three literal characters before any '*'")
    return value


def enforce_query_scope(esql: str, tenant_id: uuid.UUID | str) -> str:
    """The ES|QL that may be run: its source clause must be `FROM <allowed indices>` (checked with the same rules as index_pattern), and when NL_QUERY_TENANT_FIELD is set the caller's tenant predicate is added right after it.
    Applied to the FINAL query, so it holds whether the deterministic translator or an LLM wrote it. Raises QueryScopeError."""
    m = _SOURCE_HEAD_RE.match(esql)
    if m is None:
        raise QueryScopeError("the query does not begin with a plain FROM <indices> source clause")
    validate_index_pattern(re.sub(r"\s+", "", m.group("src")))
    field = (settings.NL_QUERY_TENANT_FIELD or "").strip()
    if not field:
        return esql
    if not _FIELD_NAME_RE.match(field):
        raise QueryScopeError("NL_QUERY_TENANT_FIELD is not a valid field name")
    return f'{m.group("head")}\n| WHERE {field} == "{tenant_id}"' + esql[m.end("head"):]


# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class NLQueryTranslateRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=10,
        description="Plain-English security question (e.g. 'Show failed logins per user in the last 24 h').",
    )
    index_pattern: str = Field(
        "logs-*,aisoc-events-*",
        description="Elasticsearch index pattern to scope the ES|QL query.",
    )
    time_range_hours: int = Field(
        24,
        ge=1,
        le=8760,
        description="Look-back window in hours.",
    )

    @field_validator("index_pattern")
    @classmethod
    def _index_pattern_names_only_indices(cls, v: str) -> str:
        try:
            return validate_index_pattern(v)
        except QueryScopeError as exc:
            raise ValueError(str(exc)) from exc


class NLQueryTranslateResponse(BaseModel):
    request_id: uuid.UUID
    question: str
    esql: str
    spl: str
    kql: str
    explanation: str
    created_at: datetime
    # Translator metadata — surfaces which engine produced the query so the
    # UI can flag deterministic vs. LLM-assisted answers.
    engine: str = Field("deterministic", description="`deterministic` or `llm`.")
    grammar_validated: bool = Field(True, description="True if every emitted query passed grammar checks.")


class NLQueryExecuteRequest(NLQueryTranslateRequest):
    es_url: str | None = Field(
        None,
        description="Override Elasticsearch URL (defaults to settings.ES_URL if set).",
    )
    es_api_key: str | None = Field(
        None,
        description="Override ES API key (defaults to settings.ES_API_KEY if set).",
    )
    max_rows: int = Field(500, ge=1, le=5000)


class QueryResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total_rows: int
    took_ms: int | None = None


class NLQueryExecuteResponse(NLQueryTranslateResponse):
    result: QueryResult | None = None
    execution_error: str | None = None


# ────────────────────────────────────────────────────────────────────────────
# Translation orchestration
# ────────────────────────────────────────────────────────────────────────────


async def _translate(
    question: str,
    index_pattern: str,
    time_range_hours: int,
) -> tuple[TranslatedQuery, str]:
    """Translate *question* into ES|QL / SPL / KQL.

    Returns a tuple of ``(TranslatedQuery, engine)`` where ``engine`` is
    either ``"deterministic"`` or ``"llm"``. The deterministic translator is
    always run first so that the response is guaranteed to be grammar-valid;
    if an LLM API key is configured *and* the air-gap policy allows the
    outbound call, we attempt to enhance the result with an LLM-generated
    translation, but fall back to the deterministic output on any error.
    """

    nl = NLQuery(
        question=question,
        index_pattern=index_pattern,
        time_range_hours=time_range_hours,
    )
    deterministic = deterministic_translate(
        question,
        index_pattern=index_pattern,
        time_range_hours=time_range_hours,
    )

    api_key = getattr(settings, "OPENAI_API_KEY", None) or getattr(settings, "LLM_API_KEY", None)
    if not api_key:
        return deterministic, "deterministic"

    completions_url = "https://api.openai.com/v1/chat/completions"
    try:
        enforce_airgap_for_url(completions_url)
    except AirgapViolation:
        return deterministic, "deterministic"

    enhanced = await enhance_with_llm(nl, api_key=api_key, fallback=deterministic)
    engine = "llm" if enhanced is not deterministic else "deterministic"
    return enhanced, engine


# ────────────────────────────────────────────────────────────────────────────
# Elasticsearch execution helper
# ────────────────────────────────────────────────────────────────────────────


async def _execute_esql(esql: str, es_url: str, es_api_key: str, max_rows: int) -> QueryResult:
    """Run an ES|QL query against Elasticsearch and return structured results.

    Thin adapter around :func:`app.services.esql_runner.run_esql_query` so the
    request-scoped endpoint and the background hunt scheduler share one code
    path for the outbound POST, the SSRF guard, the air-gap enforcement, and
    the LIMIT-clause normalisation.
    """
    result = await run_esql_query(
        esql=esql,
        es_url=es_url,
        es_api_key=es_api_key,
        max_rows=max_rows,
    )
    # ``ESQLResult`` exposes the post-LIMIT row list directly; the public
    # ``QueryResult`` schema carries an explicit ``total_rows`` for legacy
    # API consumers, but it's always ``len(rows)`` after the runner has
    # enforced the cap (Elasticsearch doesn't return a row total for ES|QL,
    # and we don't run a second count query just to populate the field).
    return QueryResult(
        columns=result.columns,
        rows=result.rows,
        total_rows=len(result.rows),
        took_ms=result.took_ms,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/translate",
    response_model=NLQueryTranslateResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate a natural-language security question to ES|QL / SPL / KQL",
    dependencies=[Depends(require_permission("lake:query"))],
)
async def translate_query(
    body: NLQueryTranslateRequest,
    user: AuthUser,
) -> NLQueryTranslateResponse:
    translated, engine = await _translate(body.question, body.index_pattern, body.time_range_hours)
    try:
        scoped_esql = enforce_query_scope(translated.esql, user.tenant_id)
    except QueryScopeError as exc:
        raise HTTPException(status_code=422, detail=f"The generated query was refused: {exc}") from exc
    return NLQueryTranslateResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=scoped_esql,
        spl=translated.spl,
        kql=translated.kql,
        explanation=translated.explanation,
        created_at=datetime.now(UTC),
        engine=engine,
        grammar_validated=True,
    )


@router.post(
    "/execute",
    response_model=NLQueryExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate NL question and execute ES|QL against Elasticsearch",
    dependencies=[Depends(require_permission("lake:query"))],
)
async def execute_query(
    body: NLQueryExecuteRequest,
    user: AuthUser,
) -> NLQueryExecuteResponse:
    translated, engine = await _translate(body.question, body.index_pattern, body.time_range_hours)
    try:
        scoped_esql = enforce_query_scope(translated.esql, user.tenant_id)
        scope_error = None
    except QueryScopeError as exc:
        scoped_esql, scope_error = translated.esql, str(exc)

    base = NLQueryExecuteResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=scoped_esql,
        spl=translated.spl,
        kql=translated.kql,
        explanation=translated.explanation,
        created_at=datetime.now(UTC),
        engine=engine,
        grammar_validated=True,
    )

    if scope_error is not None:
        # Whoever wrote the query (the deterministic translator or an LLM steered by the question), it names something the caller may not read: nothing is run.
        base.execution_error = f"Refusing to execute: {scope_error}."
        return base

    # Always resolve the ES URL from server-side settings — never from
    # user-supplied body fields — to prevent partial-SSRF attacks
    # (CodeQL py/partial-ssrf).
    try:
        es_url, es_api_key = resolve_es_credentials()
    except ESQLNotConfigured:
        base.execution_error = "ES_URL or ES_API_KEY not configured. Set them in environment variables."
        return base

    try:
        base.result = await _execute_esql(
            scoped_esql,
            es_url=es_url,
            es_api_key=es_api_key,
            max_rows=body.max_rows,
        )
    except AirgapViolation as exc:
        base.execution_error = (
            f"Air-gapped policy refused outbound request: {exc}. "
            "Add the Elasticsearch host to AISOC_AIRGAP_ALLOWLIST or point ES_URL at a private endpoint."
        )
    except GrammarError as exc:
        # Should never happen — every translator output is validated — but if a
        # caller somehow passes through a hand-edited query we want a clean error.
        base.execution_error = f"Refusing to execute malformed ES|QL: {exc}"
    except ESQLExecutionError as exc:
        base.execution_error = str(exc)
    except httpx.HTTPStatusError as exc:
        base.execution_error = f"ES query failed ({exc.response.status_code}): {exc.response.text[:500]}"
    except Exception as exc:
        base.execution_error = str(exc)

    return base
