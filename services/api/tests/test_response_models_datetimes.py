"""Response models that return ORM objects must accept the datetimes the ORM gives them.

Found by running the real API against real Postgres with two-tenant flows (creating things, not just reading): POST /assets, /threat-intel/feeds, /threat-intel/actors, /posture/findings, /insider-threat/peer-groups, /assets/vulnerabilities, /identity-graph/edges
and /reports/generate all WROTE the row and then crashed building their own response, because their `*Out` models declared timestamps as `str` and Pydantic v2 (the project pins >=2.7,<2.14) will not turn a datetime into a str. /assets and /assets/vulnerabilities also
returned SQLAlchemy's registry `MetaData()` object where the response wanted the `metadata` column (on a declarative class `metadata` is the registry, so a field named `metadata` read it). Nothing in the suite exercised these endpoints end to end.
"""
import importlib
import typing
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import MetaData

# (module, class, field): every response-model timestamp that was declared `str` and is now `datetime`.
FIXED = [
    ("mssp", "ChildTenantOut", "created_at"), ("mssp", "TenantNoteOut", "created_at"), ("mssp", "DelegationOut", "created_at"), ("mssp", "RulePackOut", "created_at"), ("mssp", "RulePackOut", "updated_at"),
    ("mssp", "PackAssignmentOut", "created_at"), ("mssp", "RuleOverrideOut", "created_at"), ("mssp", "CrossTenantIncident", "created_at"), ("mssp", "MetricsOut", "snapshot_at"), ("mssp", "ManagedTenantRow", "snapshot_at"),
    ("threat_intel", "IOCOut", "first_seen"), ("threat_intel", "IOCOut", "last_seen"), ("threat_intel", "IOCOut", "created_at"), ("threat_intel", "ThreatActorOut", "created_at"), ("threat_intel", "FeedOut", "last_polled_at"), ("threat_intel", "FeedOut", "created_at"),
    ("posture", "FindingOut", "first_detected_at"), ("posture", "FindingOut", "last_evaluated_at"), ("posture", "FindingOut", "resolved_at"), ("posture", "ScanRunOut", "started_at"), ("posture", "ScanRunOut", "completed_at"),
    ("insider_threat", "RiskProfileOut", "last_evaluated_at"), ("insider_threat", "RiskProfileOut", "updated_at"), ("insider_threat", "IndicatorOut", "acknowledged_at"), ("insider_threat", "IndicatorOut", "occurred_at"), ("insider_threat", "PeerGroupOut", "created_at"),
    ("identity_graph", "NodeOut", "created_at"), ("identity_graph", "NodeOut", "updated_at"), ("identity_graph", "EdgeOut", "valid_from"), ("identity_graph", "AlertLinkOut", "created_at"),
    ("reports", "TemplateOut", "last_run_at"), ("reports", "TemplateOut", "created_at"), ("reports", "TemplateOut", "updated_at"), ("reports", "ArtefactOut", "created_at"), ("reports", "ArtefactOut", "delivered_at"), ("reports", "ArtefactOut", "period_start"), ("reports", "ArtefactOut", "period_end"),
    ("remediation", "MaturityOut", "changed_at"), ("remediation", "MaturityOut", "created_at"), ("remediation", "GateLogOut", "created_at"), ("remediation", "WhitelistOut", "created_at"),
    ("assets", "AssetOut", "created_at"), ("assets", "AssetOut", "updated_at"), ("assets", "AssetOut", "last_seen"), ("assets", "AssetOut", "first_seen"), ("assets", "VulnerabilityOut", "first_found"), ("assets", "VulnerabilityOut", "last_found"), ("assets", "VulnerabilityOut", "remediated_at"),
]


def model(mod: str, cls: str):
    return getattr(importlib.import_module(f"app.api.v1.endpoints.{mod}"), cls)


@pytest.mark.parametrize("mod,cls,field", FIXED, ids=[f"{m}.{c}.{f}" for m, c, f in FIXED])
def test_the_timestamp_is_declared_as_a_datetime_not_a_string(mod, cls, field):
    ann = model(mod, cls).model_fields[field].annotation
    assert datetime in typing.get_args(ann) or ann is datetime, f"{cls}.{field} is {ann}"


def sample(ann, name):
    origin = typing.get_origin(ann)
    # only unwrap Optional/Union: for dict[str, Any] or list[str] the args are the element types, not alternatives
    t = next((a for a in typing.get_args(ann) if a is not type(None)), ann) if origin in (typing.Union, getattr(__import__("types"), "UnionType", None)) else ann
    if t is datetime:
        return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    if t in (str,):
        return f"sample-{name}"
    if t is int:
        return 1
    if t is float:
        return 1.0
    if t is bool:
        return True
    if typing.get_origin(t) is list or t is list:
        return []
    if typing.get_origin(t) is dict or t is dict:
        return {}
    import uuid

    if t is uuid.UUID:
        return uuid.uuid4()
    return None


def orm_like(mdl, **over):
    """What the ORM hands over: every attribute the model reads, with REAL datetimes, and (as on any declarative class) `metadata` being the registry's MetaData, not the column."""
    values = {}
    for name, f in mdl.model_fields.items():
        if name == "metadata":
            continue
        values[name] = sample(f.annotation, name) if f.is_required() else (f.get_default(call_default_factory=True))
    values["metadata"] = MetaData()
    values.update(over)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("mod,cls", sorted({(m, c) for m, c, _ in FIXED}), ids=lambda v: v if isinstance(v, str) else None)
def test_every_fixed_model_validates_from_an_orm_like_object_with_real_datetimes(mod, cls):
    mdl = model(mod, cls)
    obj = orm_like(mdl, asset_metadata={"k": 1})
    out = mdl.model_validate(obj)
    for m, c, f in FIXED:
        if (m, c) == (mod, cls):
            assert getattr(out, f) is None or isinstance(getattr(out, f), datetime)


@pytest.mark.parametrize("mod,cls", sorted({(m, c) for m, c, _ in FIXED}), ids=lambda v: v if isinstance(v, str) else None)
def test_they_still_accept_ISO_strings_for_handlers_that_format_by_hand(mod, cls):
    mdl = model(mod, cls)
    fixed = set(FIXED)
    data = {n: ("2026-01-02T03:04:05+00:00" if (mod, cls, n) in fixed else sample(f.annotation, n)) for n, f in mdl.model_fields.items() if f.is_required() or (mod, cls, n) in fixed}
    data = {k: v for k, v in data.items() if k != "metadata"}
    assert mdl.model_validate({**data, "asset_metadata": {}} if cls in ("AssetOut", "VulnerabilityOut") else data)


class TestTheMetadataCollision:
    """On a declarative class `metadata` is the registry, so a response field named `metadata` read MetaData() instead of the JSON column."""

    @pytest.mark.parametrize("mod,cls", [("assets", "AssetOut"), ("assets", "VulnerabilityOut")])
    def test_the_real_column_is_read_and_the_registry_is_ignored(self, mod, cls):
        mdl = model(mod, cls)
        out = mdl.model_validate(orm_like(mdl, asset_metadata={"owner": "ops", "n": 2}))
        assert out.metadata == {"owner": "ops", "n": 2}

    @pytest.mark.parametrize("mod,cls", [("assets", "AssetOut"), ("assets", "VulnerabilityOut")])
    def test_it_is_still_serialised_as_metadata(self, mod, cls):
        mdl = model(mod, cls)
        dumped = mdl.model_validate(orm_like(mdl, asset_metadata={"k": "v"})).model_dump(mode="json")
        assert dumped["metadata"] == {"k": "v"} and "asset_metadata" not in dumped

    @pytest.mark.parametrize("mod,cls", [("assets", "AssetOut"), ("assets", "VulnerabilityOut")])
    def test_a_missing_column_gives_an_empty_dict_not_a_crash(self, mod, cls):
        mdl = model(mod, cls)
        obj = orm_like(mdl)  # carries the registry `metadata` but no `asset_metadata` attribute at all
        assert not hasattr(obj, "asset_metadata")
        assert mdl.model_validate(obj).metadata == {}

    @pytest.mark.parametrize("mod,cls", [("assets", "AssetOut"), ("assets", "VulnerabilityOut")])
    def test_a_NULL_metadata_column_gives_an_empty_dict_instead_of_failing_the_response(self, mod, cls):
        mdl = model(mod, cls)
        assert mdl.model_validate(orm_like(mdl, asset_metadata=None)).metadata == {}

    @pytest.mark.parametrize("mod,cls", [("assets", "AssetOut"), ("assets", "VulnerabilityOut")])
    def test_populating_by_the_public_name_still_works(self, mod, cls):
        mdl = model(mod, cls)
        data = {n: sample(f.annotation, n) for n, f in mdl.model_fields.items() if f.is_required() and n != "metadata"}
        assert mdl.model_validate({**data, "metadata": {"a": 1}}).metadata == {"a": 1}

    def test_the_registry_object_really_is_what_the_old_model_would_have_read(self):
        from app.models.asset import Asset

        assert isinstance(Asset.metadata, MetaData)
