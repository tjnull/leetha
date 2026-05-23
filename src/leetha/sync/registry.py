"""Feed catalog for upstream fingerprint data feeds.

Maintains an indexed catalog of all upstream data feeds used by leetha
for passive device fingerprinting. Covers IEEE OUI databases, p0f
signatures, Huginn-Muninn datasets, IANA enterprise numbers, and
TLS fingerprint collections (JA3/JA4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator


@dataclass(frozen=True)
class FeedSource:
    """Descriptor for a single upstream fingerprint data feed."""

    key: str
    title: str
    endpoint: str
    kind: str  # "csv", "json", "text", "git_multifile"
    summary: str
    refresh_days: int = 7

    # Backward-compatible property aliases
    @property
    def name(self) -> str:
        return self.key

    @property
    def display_name(self) -> str:
        return self.title

    @property
    def url(self) -> str:
        return self.endpoint

    @property
    def source_type(self) -> str:
        return self.kind

    @property
    def description(self) -> str:
        return self.summary

    @property
    def default_interval_days(self) -> int:
        return self.refresh_days


# Keep old name available
SourceConfig = FeedSource


def _build_default_feeds() -> list[FeedSource]:
    """Construct the built-in feed definitions as a flat list."""
    return [
        FeedSource(
            key="ieee_oui",
            title="OUI Master Database",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/OUI-Master-Database/master/LISTS/master_oui.csv",
            kind="csv",
            summary=(
                "IEEE OUI Master Database -- MAC-address to manufacturer"
                " mapping with 86K+ entries including device types"
            ),
        ),
        FeedSource(
            key="p0f",
            title="p0f TCP/IP Fingerprints",
            endpoint="https://raw.githubusercontent.com/p0f/p0f/master/p0f.fp",
            kind="text",
            summary=(
                "p0f passive TCP/IP stack fingerprints for OS"
                " identification (~200KB)"
            ),
        ),
        FeedSource(
            key="huginn_devices",
            title="Huginn-Muninn Devices",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Devices/json/device.json",
            kind="json",
            summary=(
                "Huginn-Muninn hierarchical device classification"
                " profiles (116K records)"
            ),
        ),
        FeedSource(
            key="huginn_combinations",
            title="Huginn-Muninn DHCP Combinations",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Combinations/json/dhcp_combinations.json",
            kind="json",
            summary=(
                "Huginn-Muninn DHCP combination table -- links DHCP"
                " fingerprints to device profiles with names and types"
            ),
        ),
        FeedSource(
            key="huginn_dhcp",
            title="Huginn-Muninn DHCP Signatures",
            # Upstream renamed dhcp_signature.json -> split dhcp_fingerprint_partNN.json
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCP_Signatures/json/",
            kind="git_multifile",
            summary=(
                "Huginn-Muninn DHCP Option 55 fingerprints -- 368K"
                " signatures (2-part split)"
            ),
        ),
        FeedSource(
            key="huginn_dhcp_vendor",
            title="Huginn-Muninn DHCP Vendors",
            # Upstream renamed dhcp_vendor.json -> split dhcp_vendor_partNN.json
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCP_Vendors/json/",
            kind="git_multifile",
            summary=(
                "Huginn-Muninn DHCP vendor class identifiers -- 425K"
                " vendor IDs (2-part split)"
            ),
        ),
        FeedSource(
            key="huginn_dhcpv6",
            title="Huginn-Muninn DHCPv6 Signatures",
            # Upstream renamed dhcp6_signature.json -> dhcpv6_signature.json
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCPv6_Signatures/json/dhcpv6_signature.json",
            kind="json",
            summary=(
                "Huginn-Muninn DHCPv6 option request patterns for"
                " IPv6 fingerprinting"
            ),
        ),
        FeedSource(
            key="huginn_dhcpv6_enterprise",
            title="Huginn-Muninn DHCPv6 Enterprise",
            # Upstream renamed dhcp6_enterprise.json -> dhcpv6_enterprise.json
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCPv6_Enterprise/json/dhcpv6_enterprise.json",
            kind="json",
            summary=(
                "Huginn-Muninn DHCPv6 enterprise identifiers -- 58K"
                " vendor IDs for IPv6"
            ),
        ),
        FeedSource(
            key="huginn_mac_vendors",
            title="Huginn-Muninn MAC Vendors",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/MAC_Vendors/json/",
            kind="git_multifile",
            summary=(
                "Huginn-Muninn MAC vendor database -- 10.1M"
                " MAC-to-vendor records across 31 JSON files"
            ),
        ),
        FeedSource(
            key="iana_enterprise",
            title="IANA Enterprise Numbers",
            endpoint="https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers",
            kind="csv",
            summary=(
                "IANA Private Enterprise Numbers -- maps enterprise"
                " IDs to vendor names for DHCPv6"
            ),
        ),
        FeedSource(
            key="ja3_fingerprints",
            title="JA3 TLS Fingerprints",
            endpoint="https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv",
            kind="csv",
            summary=(
                "Salesforce JA3 TLS Client Hello fingerprint database"
                " (archived -- OSX/Linux application fingerprints)"
            ),
        ),
        FeedSource(
            key="ja4_fingerprints",
            title="JA4 TLS Fingerprints",
            endpoint="https://ja4db.com/api/read/",
            kind="json",
            summary=(
                "FoxIO JA4+ fingerprint database for TLS"
                " identification"
            ),
        ),
        # Satori fingerprints -- annotated device fingerprints from Huginn-Muninn
        FeedSource(
            key="satori_dhcp",
            title="Satori DHCP Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/dhcp.json",
            kind="json",
            summary="Satori annotated DHCP fingerprints with full device attribution (481 entries)",
        ),
        FeedSource(
            key="satori_useragent",
            title="Satori User-Agent Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/webuseragent.json",
            kind="json",
            summary="Satori User-Agent to device mappings (899 entries)",
        ),
        FeedSource(
            key="satori_tcp",
            title="Satori TCP Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/tcp.json",
            kind="json",
            summary="Satori TCP/IP stack fingerprints extending p0f coverage (184 entries)",
        ),
        FeedSource(
            key="satori_smb",
            title="Satori SMB Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/smb.json",
            kind="json",
            summary="Satori SMB native OS and LanMan string fingerprints (89 entries)",
        ),
        FeedSource(
            key="satori_ssh",
            title="Satori SSH Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/ssh.json",
            kind="json",
            summary="Satori SSH banner to device mapping (67 entries)",
        ),
        FeedSource(
            key="satori_web",
            title="Satori HTTP Server Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/web.json",
            kind="json",
            summary="Satori HTTP Server header fingerprints (67 entries)",
        ),
        FeedSource(
            key="satori_sip",
            title="Satori SIP Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/sip.json",
            kind="json",
            summary="Satori SIP User-Agent fingerprints for VoIP phones (25 entries)",
        ),
        FeedSource(
            key="satori_ntp",
            title="Satori NTP Fingerprints",
            endpoint="https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/ntp.json",
            kind="json",
            summary="Satori NTP client fingerprints (25 entries)",
        ),
    ]


class FeedCatalog:
    """Indexed catalog of all known fingerprint data feeds.

    Feeds are stored in an ordered dict keyed by their unique key string.
    Use ``enumerate()`` to iterate all feeds or ``lookup(key)`` to fetch
    a specific one.
    """

    def __init__(self) -> None:
        self._index: dict[str, FeedSource] = {}
        for feed in _build_default_feeds():
            self._index[feed.key] = feed

    # -- primary API (new names) ------------------------------------------

    def enumerate(self) -> list[FeedSource]:
        """Return every registered feed as a list."""
        return list(self._index.values())

    def lookup(self, key: str) -> FeedSource | None:
        """Find a feed by its key, returning *None* when absent."""
        return self._index.get(key)

    def keys(self) -> list[str]:
        """Return all registered feed keys."""
        return list(self._index.keys())

    def __len__(self) -> int:
        return len(self._index)

    def __iter__(self) -> Iterator[FeedSource]:
        return iter(self._index.values())

    def __contains__(self, key: str) -> bool:
        return key in self._index

    # -- backward-compatible aliases --------------------------------------

    def list_sources(self) -> list[FeedSource]:
        """Alias for ``enumerate()``."""
        return self.enumerate()

    def get_source(self, name: str) -> FeedSource | None:
        """Alias for ``lookup()``."""
        return self.lookup(name)


# Backward-compatible alias
SourceRegistry = FeedCatalog
