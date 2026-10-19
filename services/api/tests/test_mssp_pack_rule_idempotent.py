"""Adding the same rule to a pack twice is idempotent, not a 500.

The link's primary key is (pack_id, rule_id), and the handler inserted without looking, so a double-click or a retried request raised an unhandled IntegrityError.
"""

import asyncio
import uuid
from types import SimpleNamespace

from app.api.v1.endpoints import mssp
from app.db.database import Base
from app.models.detection_rule import DetectionRule
from app.models.mssp import MSSPRulePack, MSSPRulePackRule
from app.models.tenant import Tenant
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def test_adding_the_same_rule_twice_returns_ok_and_stores_one_link():
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(
                lambda conn: Base.metadata.create_all(
                    conn, tables=[m.__table__ for m in (Tenant, DetectionRule, MSSPRulePack, MSSPRulePackRule)]
                )
            )
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            parent = Tenant(id=uuid.uuid4(), name="msp", slug=f"msp-{uuid.uuid4().hex[:6]}")
            s.add(parent)
            await s.flush()
            pack = MSSPRulePack(id=uuid.uuid4(), parent_tenant_id=parent.id, name="pack")
            rule = DetectionRule(
                id=uuid.uuid4(),
                name="r",
                rule_language="sigma",
                rule_body="b",
                category="x",
                tenant_id=parent.id,
                is_builtin=False,
                status="active",
            )
            s.add_all([pack, rule])
            await s.commit()

            user = SimpleNamespace(tenant_id=parent.id)
            body = mssp.RulePackRuleAdd(rule_id=rule.id)
            first = await mssp.add_rule_to_pack(pack.id, body, db=s, current_user=user)
            second = await mssp.add_rule_to_pack(pack.id, body, db=s, current_user=user)
            assert first["status"] == "ok" and second["status"] == "ok"
            count = (await s.execute(select(func.count()).select_from(MSSPRulePackRule))).scalar_one()
            assert count == 1
        await engine.dispose()

    asyncio.run(main())
