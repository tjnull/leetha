"""Feed registry / manifest consistency checks.

These guard against the upstream Huginn-Muninn repo reorganizing its
JSON exports out from under us (which silently 404'd several feeds:
DHCP_Signatures and DHCP_Vendors were split into ``_partNN`` shards,
DHCPv6 files were renamed ``dhcp6_*`` → ``dhcpv6_*``, and MAC_Vendors
moved from ``mac_vendor_pNN_cN`` to ``mac_vendor_partNN``).

The structural tests run offline. The live-URL test is marked
``network`` and skipped by default.
"""

import pytest

from leetha.sync.registry import FeedCatalog
from leetha.sync import MULTIFILE_MANIFESTS, PARSER_MAP, CACHE_NAMES
from leetha.sync import parsers


def test_every_feed_has_a_parser():
    cat = FeedCatalog()
    for feed in cat.enumerate():
        assert feed.key in PARSER_MAP, f"feed {feed.key} has no PARSER_MAP entry"
        fn_name = PARSER_MAP[feed.key]
        assert hasattr(parsers, fn_name), f"parser {fn_name} missing for {feed.key}"


def test_git_multifile_feeds_have_manifests():
    cat = FeedCatalog()
    for feed in cat.enumerate():
        if feed.kind == "git_multifile":
            assert feed.key in MULTIFILE_MANIFESTS, (
                f"git_multifile feed {feed.key} has no MULTIFILE_MANIFESTS entry"
            )
            assert MULTIFILE_MANIFESTS[feed.key], f"empty manifest for {feed.key}"
            # multifile endpoints must be a directory base (trailing slash)
            assert feed.endpoint.endswith("/"), (
                f"git_multifile feed {feed.key} endpoint must end with '/': {feed.endpoint}"
            )


def test_single_file_github_feeds_point_at_a_file():
    """Single-file feeds served from GitHub raw must name a file, not a
    directory. (API endpoints like ja4db.com/api/read/ legitimately end
    in '/', so this only covers raw.githubusercontent.com.)"""
    cat = FeedCatalog()
    for feed in cat.enumerate():
        if feed.kind in ("json", "csv", "text") and "raw.githubusercontent.com" in feed.endpoint:
            assert not feed.endpoint.endswith("/"), (
                f"single-file feed {feed.key} endpoint should not be a directory: {feed.endpoint}"
            )
            assert feed.endpoint.endswith(".json") or feed.endpoint.endswith(".csv") \
                or feed.endpoint.endswith(".fp") or feed.endpoint.endswith(".txt"), (
                f"single-file feed {feed.key} endpoint should name a file: {feed.endpoint}"
            )


def test_no_stale_dhcp6_naming_in_huginn_urls():
    """Upstream renamed dhcp6_* to dhcpv6_*; pin so we don't regress."""
    cat = FeedCatalog()
    for feed in cat.enumerate():
        if "Huginn-Muninn" in feed.endpoint:
            assert "dhcp6_" not in feed.endpoint, (
                f"{feed.key} still uses stale 'dhcp6_' naming: {feed.endpoint}"
            )
            # The old single-file DHCP signature/vendor names are gone too.
            assert "dhcp_signature.json" not in feed.endpoint
            assert "dhcp_vendor.json" not in feed.endpoint


def test_mac_vendors_manifest_uses_part_naming():
    files = MULTIFILE_MANIFESTS["huginn_mac_vendors"]
    # 34 sequential parts + one trailing p35_c1 shard = 35 files
    assert len(files) == 35, f"expected 35 mac_vendor files, got {len(files)}"
    assert "mac_vendor_part01.json" in files
    assert "mac_vendor_part34.json" in files
    assert "mac_vendor_p35_c1.json" in files
    # No stale pNN_cN naming for parts 1-34
    assert not any(f.startswith("mac_vendor_p01_c") for f in files)


def test_dhcp_split_manifests_present():
    assert MULTIFILE_MANIFESTS["huginn_dhcp"] == [
        "dhcp_fingerprint_part01.json",
        "dhcp_fingerprint_part02.json",
    ]
    assert MULTIFILE_MANIFESTS["huginn_dhcp_vendor"] == [
        "dhcp_vendor_part01.json",
        "dhcp_vendor_part02.json",
    ]


def test_dhcpv6_enterprise_uses_dedicated_parser():
    """The enterprise feed must use the enterprise parser (which keeps
    the ``organization`` field), not the plain dhcpv6 signature parser."""
    assert PARSER_MAP["huginn_dhcpv6_enterprise"] == "parse_huginn_dhcpv6_enterprise"


@pytest.mark.network
def test_all_huginn_endpoints_resolve():
    """Live check — every Huginn feed URL (and the first file of each
    multifile manifest) must return HTTP 200. Skipped unless
    ``-m network`` is passed."""
    import urllib.request

    cat = FeedCatalog()
    failures = []
    for feed in cat.enumerate():
        if "Huginn-Muninn" not in feed.endpoint:
            continue
        urls = []
        if feed.kind == "git_multifile":
            for fn in MULTIFILE_MANIFESTS[feed.key]:
                urls.append(feed.endpoint + fn)
        else:
            urls.append(feed.endpoint)
        for url in urls:
            try:
                req = urllib.request.Request(url, method="HEAD",
                                             headers={"User-Agent": "leetha-test"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    if resp.status != 200:
                        failures.append((url, resp.status))
            except Exception as exc:  # noqa: BLE001
                failures.append((url, str(exc)))
    assert not failures, f"feed URLs failed: {failures}"
