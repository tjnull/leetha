"""Feed registry / manifest consistency checks.

These guard against the upstream Huginn-Muninn repo reorganizing its
JSON exports out from under us, and pin the feed URLs to the layout that
actually exists in the repo today:

  - DHCP_Signatures/json/dhcp_signature.json   (single file)
  - DHCP_Vendors/json/dhcp_vendor.json         (single file)
  - DHCPv6_Signatures/json/dhcp6_signature.json
  - DHCPv6_Enterprise/json/dhcp6_enterprise.json

The MAC_Vendors feed was intentionally dropped -- upstream's export is
99.7% "Unknown MAC Vendor (xxxxxx)" placeholder rows and added only 5
real vendors over the IEEE OUI Master Database we already sync.

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


def test_no_orphan_manifests():
    """Every MULTIFILE_MANIFESTS key must map to a git_multifile feed."""
    cat = FeedCatalog()
    multifile_keys = {f.key for f in cat.enumerate() if f.kind == "git_multifile"}
    for key in MULTIFILE_MANIFESTS:
        assert key in multifile_keys, (
            f"manifest {key!r} has no matching git_multifile feed"
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


def test_huginn_dhcp_feeds_use_upstream_filenames():
    """Pin the DHCP/DHCPv6 feeds to the filenames that exist upstream so a
    mistaken rename (e.g. dhcp6_ -> dhcpv6_, or a non-existent _partNN
    split) can't silently 404 us again."""
    cat = FeedCatalog()
    by_key = {f.key: f for f in cat.enumerate()}

    assert by_key["huginn_dhcp"].endpoint.endswith(
        "/DHCP_Signatures/json/dhcp_signature.json"
    )
    assert by_key["huginn_dhcp"].kind == "json"

    assert by_key["huginn_dhcp_vendor"].endpoint.endswith(
        "/DHCP_Vendors/json/dhcp_vendor.json"
    )
    assert by_key["huginn_dhcp_vendor"].kind == "json"

    assert by_key["huginn_dhcpv6"].endpoint.endswith(
        "/DHCPv6_Signatures/json/dhcp6_signature.json"
    )
    assert by_key["huginn_dhcpv6_enterprise"].endpoint.endswith(
        "/DHCPv6_Enterprise/json/dhcp6_enterprise.json"
    )


def test_mac_vendors_feed_is_removed():
    """huginn_mac_vendors was dropped (99.7% placeholder junk); it must
    not reappear in the registry, PARSER_MAP, or any manifest."""
    cat = FeedCatalog()
    assert "huginn_mac_vendors" not in {f.key for f in cat.enumerate()}
    assert "huginn_mac_vendors" not in PARSER_MAP
    assert "huginn_mac_vendors" not in MULTIFILE_MANIFESTS


def test_dhcpv6_enterprise_uses_dedicated_parser():
    """The enterprise feed must use the enterprise parser (which keeps
    the ``organization`` field), not the plain dhcpv6 signature parser."""
    assert PARSER_MAP["huginn_dhcpv6_enterprise"] == "parse_huginn_dhcpv6_enterprise"


@pytest.mark.network
def test_all_huginn_endpoints_resolve():
    """Live check — every Huginn feed URL (and every file of each
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
