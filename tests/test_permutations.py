"""Tests for the permutation engine.

Focused on the core of the project — the variant generator. We verify:
  - correctness of each technique
  - deduplication
  - absence of the original domain in results
  - edge-case handling
  - the exclude/whitelist behavior
"""

from __future__ import annotations

from otacon import permutations
from otacon.models import PermutationType


def test_generate_excludes_original():
    """The original domain must never appear among the variants."""
    perms = permutations.generate("example.com")
    domains = {p.domain for p in perms}
    assert "example.com" not in domains


def test_generate_no_duplicates():
    """Each variant occurs exactly once."""
    perms = permutations.generate("example.com")
    domains = [p.domain for p in perms]
    assert len(domains) == len(set(domains))


def test_generate_empty_input():
    """Empty/invalid input does not crash — returns an empty list."""
    assert permutations.generate("") == []


def test_typo_omission_present():
    """Character omission: 'gogle.com' should arise from 'google.com'."""
    perms = permutations.generate("google.com")
    domains = {p.domain for p in perms}
    assert "gogle.com" in domains


def test_homoglyph_produces_unicode():
    """Homoglyphs include non-ASCII characters (Cyrillic etc.)."""
    perms = permutations.generate("paypal.com")
    homoglyphs = [p for p in perms if p.kind == PermutationType.HOMOGLYPH]
    assert any(not p.domain.isascii() for p in homoglyphs)


def test_combo_keywords():
    """Combosquatting appends bait words."""
    perms = permutations.generate("bank.com")
    domains = {p.domain for p in perms}
    assert "bank-login.com" in domains
    assert "bank-secure.com" in domains


def test_tld_swap_changes_tld():
    """TLD swap changes the suffix while keeping the name."""
    perms = permutations.generate("example.com")
    tld_swaps = [p for p in perms if p.kind == PermutationType.TLD_SWAP]
    assert any(p.domain == "example.net" for p in tld_swaps)
    assert all(p.domain.startswith("example.") for p in tld_swaps)


def test_hyphenation():
    """Hyphen insertion creates split variants."""
    perms = permutations.generate("hotmail.com")
    domains = {p.domain for p in perms}
    assert any("-" in d for d in domains)


def test_all_have_metadata():
    """Every variant has an assigned type and a non-empty description."""
    perms = permutations.generate("test.com")
    for p in perms:
        assert isinstance(p.kind, PermutationType)
        assert p.note  # technique description is not empty


def test_exclude_removes_whitelisted():
    """Domains on the whitelist do not appear in the results."""
    # 'gogle.com' is a known typo of google.com — we exclude it.
    perms = permutations.generate("google.com", exclude={"gogle.com"})
    domains = {p.domain for p in perms}
    assert "gogle.com" not in domains


def test_exclude_case_insensitive():
    """The whitelist works regardless of letter case."""
    perms = permutations.generate("google.com", exclude={"GOGLE.COM"})
    domains = {p.domain for p in perms}
    assert "gogle.com" not in domains


def test_exclude_none_is_noop():
    """No whitelist yields the same result as an empty one."""
    a = {p.domain for p in permutations.generate("test.com")}
    b = {p.domain for p in permutations.generate("test.com", exclude=set())}
    assert a == b


def test_no_invalid_dns_chars_in_homoglyphs():
    """Homoglyph variants must not contain @, (, or $ — invalid in DNS labels."""
    perms = permutations.generate("example.com")
    homoglyphs = [p for p in perms if p.kind == PermutationType.HOMOGLYPH]
    for p in homoglyphs:
        label = p.domain.split(".")[0]
        assert "@" not in label
        assert "(" not in label
        assert "$" not in label


# --- Task 04: new techniques ---

def test_soundsquat_ph_to_f():
    """'ph' → 'f' substitution: phish.com should produce fish.com."""
    perms = permutations.generate("phish.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.SOUNDSQUAT}
    assert "fish.com" in domains


def test_soundsquat_f_to_ph():
    """'f' → 'ph' substitution (two-char expansion cannot be a bitsquat)."""
    perms = permutations.generate("fish.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.SOUNDSQUAT}
    assert "phish.com" in domains


def test_soundsquat_no_self():
    """Soundsquat never returns the original label unchanged."""
    perms = permutations.generate("facebook.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.SOUNDSQUAT}
    assert "facebook.com" not in domains


def test_vowel_swap_produces_variants():
    """Vowel substitution generates at least one variant for a vowel-containing domain."""
    perms = permutations.generate("bank.com")
    vs = [p for p in perms if p.kind == PermutationType.VOWEL_SWAP]
    assert len(vs) > 0


def test_vowel_swap_replaces_vowels():
    """Vowel-swap result differs from original only in vowel positions."""
    perms = permutations.generate("test.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.VOWEL_SWAP}
    # 'e' in 'test' can become a, i, o, u
    assert any(d.startswith("tast") or d.startswith("tist") or
               d.startswith("tost") or d.startswith("tust") for d in domains)


def test_plural_adds_s():
    """Singular domain gets an -s variant."""
    perms = permutations.generate("bank.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.PLURAL}
    assert "banks.com" in domains


def test_plural_y_to_ies():
    """y → ies pluralization is multi-char and never conflicts with typo/bitsquat."""
    perms = permutations.generate("company.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.PLURAL}
    assert "companies.com" in domains


def test_subdomain_spoof_present():
    """Subdomain spoof embeds the original domain as a label of a spoof registrar."""
    perms = permutations.generate("example.com")
    subdomains = [p for p in perms if p.kind == PermutationType.SUBDOMAIN]
    assert len(subdomains) > 0
    assert any(p.domain.startswith("example.com.") for p in subdomains)


def test_subdomain_spoof_uses_all_suffixes():
    """One variant per spoof suffix is generated."""
    from otacon.permutations import _SPOOF_SUFFIXES
    perms = permutations.generate("example.com")
    sub_domains = {p.domain for p in perms if p.kind == PermutationType.SUBDOMAIN}
    for suffix in _SPOOF_SUFFIXES:
        assert f"example.com.{suffix}" in sub_domains


def test_idn_variants_are_ascii():
    """IDN variants are punycode-encoded ASCII, starting with xn--."""
    perms = permutations.generate("paypal.com")
    idn = [p for p in perms if p.kind == PermutationType.IDN]
    if idn:  # may be empty if no encodeable homoglyphs for this input
        for p in idn:
            label = p.domain.split(".")[0]
            assert label.isascii()
            assert label.startswith("xn--")


def test_idn_not_duplicated_by_homoglyph():
    """IDN variants (xn-- labels) do not appear in the homoglyph set."""
    perms = permutations.generate("paypal.com")
    homoglyph_domains = {p.domain for p in perms if p.kind == PermutationType.HOMOGLYPH}
    idn_domains = {p.domain for p in perms if p.kind == PermutationType.IDN}
    assert homoglyph_domains.isdisjoint(idn_domains)
