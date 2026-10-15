from app.services.device_identity import hostname_key, normalize_serial


def test_serial_is_trimmed_and_uppercased():
    assert normalize_serial("  5cg1 234abc ") == "5CG1234ABC"


def test_placeholder_and_junk_serials_count_as_none():
    for junk in (
        "To Be Filled By O.E.M.",
        "Default string",
        "0000000",
        "XXXXXXXX",
        "N/A",
        "none",
        "",
        "  ",
        None,
        "123",
        "System Serial Number",
        "123456789",
    ):
        assert normalize_serial(junk) is None, junk


def test_same_machine_serial_matches_across_tools_despite_formatting():
    assert normalize_serial("C02ABC123XYZ") == normalize_serial(" c02abc123xyz\n")


def test_hostname_key_ignores_case_and_domain():
    assert hostname_key("PC-01.corp.local") == hostname_key("pc-01") == "pc-01"
    assert hostname_key(None) == ""
