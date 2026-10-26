"""Tests for detection accuracy: IDN targets, diacritic variants, parking by NS/title."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pycares
import pytest

from otacon import permutations, scoring
from otacon._validate import is_valid_domain, normalize_domain
from otacon.models import DomainResult, Permutation, PermutationType
from otacon.resolver import Resolver

ZABKA = "żabka.pl"  # the brand as people type it
ZABKA_ACE = "xn--abka-99a.pl"


# --- IDN targets ------------------------------------------------------------


def test_normalize_turns_an_idn_brand_into_valid_ace() -> None:
    assert normalize_domain(ZABKA.upper()) == ZABKA_ACE
    assert is_valid_domain(normalize_domain(ZABKA))


def test_normalize_leaves_an_unencodable_name_for_validation_to_reject() -> None:
    bad = "a" * 70 + "ą.pl"  # label too long to encode
    assert normalize_domain(bad) == bad
    assert not is_valid_domain(normalize_domain(bad))


def test_idn_target_is_permuted_by_name_not_by_its_ace_prefix() -> None:
    domains = {p.domain for p in permutations.generate(ZABKA_ACE)}
    # Mutating the 'xn--' string produced junk such as 'cn--abka-...'.
    assert not any(d.startswith(("cn--", "xn--x--", "xn--n--")) for d in domains)
    assert "zabka.pl" in domains  # the plain-ASCII spelling, the classic squat


def test_from_ace_decodes_each_label_and_keeps_bad_ones() -> None:
    assert permutations._from_ace("xn--abka-99a") == "żabka"
    assert permutations._from_ace("shop.xn--abka-99a") == "shop.żabka"
    assert permutations._from_ace("xn--a") == "xn--a"  # undecodable: kept as is


# --- diacritic variants -----------------------------------------------------


def test_diacritics_add_one_mark() -> None:
    out = permutations._diacritics("allegro")
    assert {"allęgro", "allegró", "ąllegro"} <= out
    assert "allegro" not in out


def test_diacritics_drop_one_mark_or_all_of_them() -> None:
    out = permutations._diacritics("żółw")
    assert "zolw" in out  # all dropped
    assert "zółw" in out  # one dropped


def test_generate_labels_diacritic_variants() -> None:
    kinds = {p.domain: p.kind for p in permutations.generate("allegro.pl")}
    assert "allegro.pl" not in kinds
    ace = "allęgro.pl".encode("idna").decode()
    assert kinds[ace] == PermutationType.DIACRITIC


# --- parking ----------------------------------------------------------------


def _registered(**kw: object) -> DomainResult:
    return DomainResult(domain="exampled.com", kind=PermutationType.TYPO, resolves=True, **kw)  # type: ignore[arg-type]


@pytest.mark.parametrize("ns", ["ns1.sedoparking.com", "NS2.BODIS.COM.", "a.ns.parkingcrew.net"])
def test_parking_detected_from_nameservers(ns: str) -> None:
    r = scoring.score(_registered(ns_records=[ns.lower()], http_status=200), "example.com")
    assert r.is_parked


def test_parking_ns_match_is_by_domain_not_substring() -> None:
    r = scoring.score(_registered(ns_records=["ns1.notsedoparking.com"]), "example.com")
    assert not r.is_parked


def test_parking_detected_from_a_polish_for_sale_title() -> None:
    title = "exampled.com - Ta strona jest na sprzedaż!"
    assert scoring.score(_registered(page_title=title), "example.com").is_parked


def test_a_shop_selling_things_is_not_parking() -> None:
    title = "Sprzedaż hurtowa - sklep"
    assert not scoring.score(_registered(page_title=title), "example.com").is_parked


def test_parked_domain_still_scores_its_mail_server() -> None:
    r = scoring.score(_registered(ns_records=["ns1.sedoparking.com"], has_mx=True), "example.com")
    assert r.is_parked
    assert any("MX" in reason for reason in r.risk_reasons)


# --- resolver ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_one_fetches_nameservers_only_for_registered_variants() -> None:
    def reply(domain: str, rtype: str) -> MagicMock:
        if domain.startswith("live") and rtype == "A":
            records = [MagicMock(type=pycares.QUERY_TYPE_A, data=MagicMock(addr="203.0.113.5"))]
        elif domain.startswith("live") and rtype == "NS":
            records = [
                MagicMock(type=pycares.QUERY_TYPE_NS, data=MagicMock(nsdname="NS1.SEDOPARKING.COM"))
            ]
        else:
            records = []
        return MagicMock(answer=records)

    async with Resolver(check_http=False, check_whois=False) as r:
        mock = AsyncMock(side_effect=reply)
        with (
            patch.object(r._dns, "query_dns", mock),
            patch.object(r, "_probe_wildcard", AsyncMock(return_value=frozenset())),
        ):
            live = await r.check_one(Permutation(domain="live.example", kind=PermutationType.TYPO))
            dead = await r.check_one(Permutation(domain="dead.example", kind=PermutationType.TYPO))
    assert live.ns_records == ["ns1.sedoparking.com"]
    assert dead.ns_records == []
    asked_ns_for = {c.args[0] for c in mock.await_args_list if c.args[1] == "NS"}
    assert asked_ns_for == {"live.example"}


def test_parse_title_folds_nbsp_entities_into_plain_spaces() -> None:
    from otacon.resolver import _parse_title

    assert _parse_title("<title>for&nbsp;sale &#160;now&#27;</title>") == "for sale now"
