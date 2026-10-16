"""The two vendor -> client-id maps (alert intake in fusion, re-routing in the API) must name the same vendors and fields.

When they drifted, a vendor's alerts were routed to its client at intake but never moved after the client was mapped later (Blumira was missing here).
The fusion service is a separate app package, so its map is read from its source as a dict literal and compared by value.
"""

import ast
from pathlib import Path

from app.services.alert_reroute import CLIENT_ID_FIELD

FUSION = Path(__file__).resolve().parents[2] / "fusion" / "app" / "services" / "client_routing.py"


def fusion_map() -> dict[str, str]:
    for node in ast.parse(FUSION.read_text()).body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "CLIENT_ID_FIELD":
            return ast.literal_eval(node.value)
    raise AssertionError("fusion CLIENT_ID_FIELD not found")


def test_both_maps_name_the_same_vendors_and_fields():
    assert CLIENT_ID_FIELD == fusion_map()


def test_the_vendors_with_a_client_list_are_routable():
    for vendor in ("huntress", "petra", "ninjaone", "threatmate", "addigy", "blumira", "fieldeffect"):
        assert vendor in CLIENT_ID_FIELD
