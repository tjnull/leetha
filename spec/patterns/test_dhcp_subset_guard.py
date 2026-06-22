"""Short DHCP opt55 patterns must not fingerprint devices via subset matching.

Regression: a Samsung TV requesting `1,3,26,252,43,42,6,12` was confidently
mislabeled "Siemens HMI / Windows CE" because the generic 5-option pattern
`1,3,6,12,42` is a subset of its request. Short patterns may still match
EXACTLY, but must not subset-fingerprint a larger request list.
"""

from leetha.patterns.matching import match_dhcp_opt55


def test_superset_of_short_generic_pattern_does_not_misfire():
    # Superset of the 5-option Siemens pattern -> must NOT return Windows CE.
    res = match_dhcp_opt55("1,3,26,252,43,42,6,12")
    assert res is None or res.get("os_family") != "Windows CE"


def test_short_pattern_still_matches_exactly():
    res = match_dhcp_opt55("1,3,6,12,42")
    assert res is not None
    assert res["match_source"] == "dhcp_opt55_exact"


def test_modern_windows_signature_resolves_to_windows():
    res = match_dhcp_opt55("1,3,6,15,31,33,43,44,46,47,119,121,249,252")
    assert res is not None
    assert res["os_family"] == "Windows"


def test_long_specific_pattern_still_subset_matches():
    # A 6+ option pattern remains eligible for subset matching. Append an
    # extra (uncommon) option to a known multi-option fingerprint and confirm
    # we still get a (non-None) partial match for a sufficiently specific set.
    base = "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
    res = match_dhcp_opt55(base + ",250")
    assert res is not None  # partial/subset match of the long Windows pattern
