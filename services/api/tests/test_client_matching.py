from app.services.client_matching import Candidate, is_confident, normalize_name, score, suggest

TENANTS = [
    Candidate("t1", "Acme Dental"),
    Candidate("t2", "Sportsmans Finest LLC"),
    Candidate("t3", "Legendairy Milk"),
    Candidate("t4", "Oak & Pine Realty"),
]


def test_normalize_drops_company_words_punctuation_case_and_accents():
    assert normalize_name("ACME Dental, L.L.C.") == "acme dental"
    assert normalize_name("The Café Müller Inc.") == "cafe muller"
    assert normalize_name("Oak & Pine Realty") == normalize_name("Oak and Pine Realty")
    assert normalize_name("Sportsman's Finest") == "sportsmans finest"
    assert normalize_name("  ") == ""


def test_the_same_customer_spelled_differently_is_an_exact_match():
    for spelling in ("Acme Dental, LLC", "ACME DENTAL", "acme-dental inc"):
        top = suggest(spelling, TENANTS)[0]
        assert (top.tenant_id, top.score) == ("t1", 1.0), spelling
    assert is_confident(suggest("Acme Dental, LLC", TENANTS))


def test_a_name_that_contains_the_other_is_suggested_but_not_confident():
    s = suggest("Sportsmans Finest Outfitters", TENANTS)
    assert s[0].tenant_id == "t2" and 0.6 <= s[0].score < 1.0
    assert not is_confident(s)


def test_unrelated_names_get_no_suggestion():
    assert suggest("Zenith Plumbing", TENANTS) == []
    assert score("", "Acme") == 0.0


def test_a_near_misspelling_ranks_the_right_tenant_first():
    assert suggest("Legendary Milk", TENANTS)[0].tenant_id == "t3"


def test_two_tenants_with_the_same_normalized_name_are_never_confident():
    twins = [Candidate("a", "Acme Dental LLC"), Candidate("b", "Acme Dental Inc")]
    s = suggest("Acme Dental", twins)
    assert [x.score for x in s] == [1.0, 1.0]
    assert not is_confident(s)
