"""No endpoint on a PLAIN session fetches a tenant-owned row by id without ever looking at that row's tenant.

Why a plain session matters: a get_db session carries no tenant and the RLS policies are fail-open, so nothing but the handler's own check
stops one tenant reading another's row by id. The bug this pins: `POST /mssp/rule-packs/{pack_id}/rules` checked that the PACK was the
caller's, then fetched the rule with `rule = await db.get(DetectionRule, body.rule_id)` and never looked at `rule.tenant_id`, so any
tenant's private rule could be attached to the caller's pack and delivered to its children (reproduced on a real Postgres; fixed in
934ceb7e).
A function-wide "mentions tenant_id" test would have MISSED it (the function does mention it, for the pack), so the check is PER OBJECT:
for `x = await db.get(<model with a tenant_id column>, id)`, the function must examine `x.tenant_id` somewhere. A heuristic with a stated
limit: it sees only this shape (an assignment from `.get()` on a model that has a tenant_id column), not `select(...).where(Model.id ==
...)`, not a fetch inside a helper, and not a check that compares a different attribute. It is a lower bound that stops the exact mistake
recurring, and it carries its own positive control.
"""

import ast
from pathlib import Path

from app.db.database import Base
from app.main import app  # noqa: F401  (imports every model)

ENDPOINTS = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"
OWNED = {m.class_.__name__ for m in Base.registry.mappers if hasattr(m.class_, "__table__") and "tenant_id" in m.class_.__table__.columns}

# (file, function, model): a fetch whose row's tenant is knowingly not examined, with the reason. Empty: there is none.
ALLOWED: dict[tuple[str, str, str], str] = {}


def unchecked_fetches(source: str) -> list[tuple[str, str]]:
    """(function, model) for every `x = [await] db.get(<owned model>, id)` on a plain session where `x.tenant_id` is never examined in
    that function."""
    found = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        header = "\n".join(
            ast.unparse(x)
            for x in [d for d in fn.args.defaults + fn.args.kw_defaults if d is not None]
            + [a.annotation for a in fn.args.args + fn.args.kwonlyargs if a.annotation is not None]
        )
        if "TenantDBSession" in header or "get_tenant_db" in header:  # an RLS-scoped session: the policy is the check
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                call = node.value.value if isinstance(node.value, ast.Await) else node.value
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "get"
                    and call.args
                    and isinstance(call.args[0], ast.Name)
                    and call.args[0].id in OWNED
                ):
                    var = node.targets[0].id
                    if not any(
                        isinstance(n, ast.Attribute) and n.attr == "tenant_id" and isinstance(n.value, ast.Name) and n.value.id == var
                        for n in ast.walk(fn)
                    ):
                        found.append((fn.name, call.args[0].id))
    return found


PRE_FIX = """
async def add_rule_to_pack(pack_id, body, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404)
    rule = await db.get(DetectionRule, body.rule_id)
    if not rule:
        raise HTTPException(status_code=404)
"""
FIXED = PRE_FIX.replace("    if not rule:\n", "    if not rule or rule.tenant_id != current_user.tenant_id:\n")


def test_the_scan_sees_models_with_a_tenant_column_including_the_one_in_the_original_bug():
    assert "DetectionRule" in OWNED and len(OWNED) > 40, "an empty model list would make the scan pass vacuously"


def test_positive_control_the_scan_flags_the_original_bug_even_though_the_function_mentions_tenant_id_for_the_pack():
    assert unchecked_fetches(PRE_FIX) == [("add_rule_to_pack", "DetectionRule")]


def test_the_same_function_with_the_ownership_check_is_clean():
    assert unchecked_fetches(FIXED) == []


def test_a_fetch_on_a_tenant_scoped_session_is_not_flagged_because_the_policy_is_the_check():
    scoped = PRE_FIX.replace("db: AsyncSession = Depends(get_db)", "db: TenantDBSession")
    assert unchecked_fetches(scoped) == []


def test_a_model_without_a_tenant_column_is_not_flagged():
    assert unchecked_fetches(PRE_FIX.replace("DetectionRule", "SomeGlobalLookupTable")) == []


def _all():
    rows = []
    for path in sorted(ENDPOINTS.glob("*.py")):
        for function, model in unchecked_fetches(path.read_text(encoding="utf-8", errors="replace")):
            rows.append((path.name, function, model))
    return rows


def test_no_endpoint_fetches_a_tenant_owned_row_by_id_on_a_plain_session_without_examining_its_tenant():
    offenders = [row for row in _all() if row not in ALLOWED]
    assert not offenders, f"fetched by id, owner never examined (add the check, or list it in ALLOWED with the reason): {offenders}"


def test_every_allowed_entry_still_exists_so_the_list_can_only_shrink():
    current = set(_all())
    stale = [key for key in ALLOWED if key not in current]
    assert not stale, f"fixed or removed, drop it from ALLOWED: {stale}"
