"""The dashboard's Connected Sources panel must list every source CORE forwards, each with its own alert count."""

from types import SimpleNamespace as NS

from app.api.v1.endpoints.metrics import build_source_stats


def _c(name, ctype, vendor=None, health="healthy"):
    return NS(name=name, connector_type=ctype, health_status=health, connector_config={"vendor": vendor} if vendor else {})


def test_each_core_vendor_is_its_own_row_with_its_own_count():
    rows = [_c("Huntress (via CORE)", "core_feed", "huntress"), _c("Petra (via CORE)", "core_feed", "petra")]
    out = build_source_stats(rows, {}, {"huntress": 291, "petra": 4})
    assert [(s.name, s.count) for s in out] == [("Huntress (via CORE)", 291), ("Petra (via CORE)", 4)]


def test_vendor_with_no_alerts_is_listed_with_zero():
    out = build_source_stats([_c("Petra (via CORE)", "core_feed", "petra")], {}, {"huntress": 5})
    assert [(s.name, s.count) for s in out] == [("Petra (via CORE)", 0)]


def test_ordinary_connectors_still_collapse_per_type():
    rows = [_c("Okta A", "okta"), _c("Okta B", "okta")]
    out = build_source_stats(rows, {"okta": 7}, {})
    assert [(s.name, s.count) for s in out] == [("Okta A", 7)]
