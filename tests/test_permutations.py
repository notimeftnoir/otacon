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


def test_idn_produces_punycode():
    """IDN variants are non-ASCII characters, normalized to Punycode."""
    perms = permutations.generate("paypal.com")
    idn = [p for p in perms if p.kind == PermutationType.IDN]
    assert len(idn) > 0
    # Check for Punycode (xn--) instead of Unicode.
    assert any(p.domain.startswith("xn--") for p in idn)


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


def test_exclude_normalizes_trailing_root_dot():
    """A whitelist entry given as a dotted FQDN ('example.net.') must still
    exclude the dotless variants every technique emits — generate() strips the
    root dot from exclusions the same way it does from the target domain."""
    perms = permutations.generate("example.com", exclude={"example.net."})
    assert "example.net" not in {p.domain for p in perms}


def test_generate_strips_surrounding_whitespace_from_subdomain_spoofs():
    """Every emitted domain must be whitespace-free even when generate() is called
    directly with an unnormalised string.

    The SUBDOMAIN technique embeds the whole input as a label, so it was the one
    place a stray space survived into the output (' example.com .login.com') and
    produced a domain that could never match the `seen` set either.
    """
    perms = permutations.generate("  example.com  ")
    assert perms
    for p in perms:
        assert p.domain == p.domain.strip()
        assert " " not in p.domain


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
    assert any(
        d.startswith("tast") or d.startswith("tist") or d.startswith("tost") or d.startswith("tust")
        for d in domains
    )


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
    assert len(idn) > 0
    for p in idn:
        label = p.domain.split(".")[0]
        assert label.isascii()
        assert label.startswith("xn--")


def test_split_domain_multi_part_tld():
    """_split_domain correctly separates label and multi-part TLD."""
    from otacon.permutations import _split_domain

    label, tld = _split_domain("example.co.uk")
    assert label == "example"
    assert tld == "co.uk"

    label, tld = _split_domain("example.com.pl")
    assert label == "example"
    assert tld == "com.pl"


def test_split_domain_strips_trailing_root_dot():
    """A trailing root dot ('example.com.') is a legal FQDN that is_valid_domain
    accepts — without stripping it here, the label/tld split collapses onto the
    empty final part, silently dropping TLD_SWAP and corrupting every other
    technique's output. See generate() parity test below."""
    from otacon.permutations import _split_domain

    assert _split_domain("example.com.") == ("example", "com")
    assert _split_domain("example.co.uk.") == ("example", "co.uk")


def test_split_domain_single_label_is_normalized():
    """The len<2 fallback must return the normalized label, not the raw input —
    a trailing dot surviving here ('COM.' -> ('com', '')) would corrupt every
    variant generate() builds from the label."""
    from otacon.permutations import _split_domain

    assert _split_domain("COM.") == ("com", "")
    assert _split_domain(" com ") == ("com", "")


def test_generate_trailing_dot_matches_bare_domain():
    """generate() must treat 'example.com.' identically to 'example.com' —
    including TLD_SWAP, which a broken split silently drops to zero."""
    bare = {(p.domain, p.kind) for p in permutations.generate("example.com")}
    dotted = {(p.domain, p.kind) for p in permutations.generate("example.com.")}
    assert dotted == bare
    assert any(p.kind == PermutationType.TLD_SWAP for p in permutations.generate("example.com."))


# --- cross-tool parity pass: homoglyph coverage, www-merge, abused TLDs ---


def test_homoglyph_covers_previously_missing_letters():
    """b, f, g, h, j, k, q, r, t, u, v, z each need a real-world lookalike.

    Verified against Unicode's confusables.txt (unicode.org/Public/security) —
    each substitution below is a documented single-codepoint confusable for
    that Latin letter, not a guess.
    """
    from otacon.permutations import _HOMOGLYPHS

    for letter in "bfghjkqrtuvz":
        assert letter in _HOMOGLYPHS, f"no homoglyph entry for {letter!r}"
        assert len(_HOMOGLYPHS[letter]) > 0


def test_homoglyph_new_letters_produce_idna_valid_variants():
    """New homoglyph substitutions must survive IDNA encoding (else unusable as a real domain)."""
    perms = permutations.generate("github.com")
    idn = [p for p in perms if p.kind == PermutationType.IDN]
    assert any(p.domain.startswith("xn--") for p in idn)


def test_www_merge_present():
    """'www' + domain merged with no dot — a very common real-world phishing vector."""
    perms = permutations.generate("example.com")
    www_merges = [p for p in perms if p.kind == PermutationType.WWW_MERGE]
    assert any(p.domain == "wwwexample.com" for p in www_merges)


def test_tld_swap_includes_abused_tlds():
    """TLD swap must include TLDs most commonly abused for phishing (Interisle/Spamhaus data)."""
    perms = permutations.generate("example.com")
    tld_swaps = {p.domain for p in perms if p.kind == PermutationType.TLD_SWAP}
    for abused in ("example.top", "example.icu", "example.cyou", "example.cc"):
        assert abused in tld_swaps


# --- keyboard layouts (QWERTZ/AZERTY) + distinct insertion technique ---


def test_qwertz_adjacency_swaps_y_and_z():
    """QWERTZ (DE/AT/CH) differs from QWERTY by swapping the y/z key positions."""
    from otacon.permutations import _QWERTY_ADJACENT, _QWERTZ_ADJACENT

    # QWERTY 't' neighbors include 'y', not 'z' -> QWERTZ must have the opposite.
    assert "y" in _QWERTY_ADJACENT["t"] and "z" not in _QWERTY_ADJACENT["t"]
    assert "z" in _QWERTZ_ADJACENT["t"] and "y" not in _QWERTZ_ADJACENT["t"]
    # The 'z' key on QWERTZ sits where 'y' sat on QWERTY, so it inherits that entry.
    assert _QWERTZ_ADJACENT["z"] == _QWERTY_ADJACENT["y"]


def test_azerty_adjacency_swaps_q_a_and_w_z():
    """AZERTY (FR) differs from QWERTY by swapping q/a and w/z key positions."""
    from otacon.permutations import _AZERTY_ADJACENT, _QWERTY_ADJACENT

    # The 'a' key on AZERTY sits where 'q' sat on QWERTY (with w/z also swapped
    # inside the neighbor string, since those keys moved too).
    expected_a = _QWERTY_ADJACENT["q"].translate(str.maketrans({"w": "z", "a": "q"}))
    assert _AZERTY_ADJACENT["a"] == expected_a


def test_keyboard_insertion_produces_supersequence_not_seen_by_other_typo_mechanisms():
    """Inserting an adjacent key (keeping the original char) differs from omission,
    duplication, transposition, and replacement — all of which drop or swap a
    character rather than adding a new one next to an unmodified original.
    """
    perms = permutations.generate("test.com")
    domains = {p.domain for p in perms if p.kind == PermutationType.TYPO}
    # 'r' is QWERTY-adjacent to the leading 't'; inserting it before keeps
    # "test" intact as a substring — impossible via omission/duplication/
    # transposition/replacement of a single character.
    assert "rtest.com" in domains
