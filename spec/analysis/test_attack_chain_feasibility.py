"""Attack chains must reflect what is actually doable on the network.

These pin the feasibility fixes:
  * NTLM-relay / domain chains require a Windows/SMB/AD environment;
  * VLAN-hopping requires actual DTP/trunk evidence (L2-007), not a
    cross-subnet heuristic (L2-008);
  * STP root-bridge takeover requires observed STP BPDUs (L2-009), not
    routine CDP/LLDP discovery (L2-006).
"""

import pytest

from leetha.analysis.attack_surface import (
    build_chains, Finding, Category, Severity,
)


def _f(rule_id, severity=Severity.HIGH, category=Category.NAME_RESOLUTION):
    return Finding(rule_id=rule_id, name=rule_id, category=category,
                   severity=severity, description="x")


class _Ctx:
    """Minimal AnalysisContext stand-in for chain-gating tests."""
    def __init__(self, domain=None, dc_ip=None, interface="eth0"):
        self.domain = domain
        self.dc_ip = dc_ip
        self.interface = interface
        # Attributes read during chain tool-command hydration:
        self.gateway_ip = None
        self.attacker_ip = None
        self.device_map = {}


def _chain_ids(findings, ctx=None):
    return {c.chain_id for c in build_chains(findings, ctx)}


def test_mdns_local_domain_does_not_satisfy_windows_env():
    # ctx.domain derived from a ubiquitous mDNS ".local" name must NOT mark
    # the network as Windows/AD — otherwise the relay chains fire everywhere.
    ids = _chain_ids([_f("NR-001")], ctx=_Ctx(domain="home.local"))
    assert "CHAIN-001" not in ids


def test_discovered_dc_does_satisfy_windows_env():
    # A Kerberos-discovered DC is real AD evidence → relay chain feasible.
    ids = _chain_ids([_f("NR-001")], ctx=_Ctx(dc_ip="192.168.1.10"))
    assert "CHAIN-001" in ids


def test_llmnr_alone_does_not_build_relay_chain_without_windows():
    # LLMNR present but no Windows/SMB/AD targets → CHAIN-001 must NOT fire.
    ids = _chain_ids([_f("NR-001")])
    assert "CHAIN-001" not in ids


def test_llmnr_with_windows_target_builds_relay_chain():
    # LLMNR + NetBIOS (Windows present) → relay is feasible → CHAIN-001 fires.
    ids = _chain_ids([_f("NR-001"), _f("NR-002")])
    assert "CHAIN-001" in ids


def test_vlan_hopping_requires_dtp_not_multisubnet():
    # L2-008 (device on multiple subnets) alone must NOT build the DTP chain.
    assert "CHAIN-002" not in _chain_ids([_f("L2-008", category=Category.LAYER2)])
    # L2-007 (actual DTP/trunk) does.
    assert "CHAIN-002" in _chain_ids([_f("L2-007", category=Category.LAYER2)])


def test_stp_takeover_requires_bpdus_not_lldp():
    # L2-006 (CDP/LLDP discovery) must NOT build the STP takeover chain.
    assert "CHAIN-010" not in _chain_ids([_f("L2-006", category=Category.LAYER2)])
    # L2-009 (STP BPDUs observed) does.
    assert "CHAIN-010" in _chain_ids([_f("L2-009", category=Category.LAYER2)])


def test_ics_chain_requires_ics_protocol():
    # An ICS protocol finding is itself the environment evidence → fires.
    ids = _chain_ids([_f("SE-009", category=Category.SERVICE_EXPLOIT)])
    assert "CHAIN-005" in ids


def test_smb_relay_domain_chain_needs_both_and_windows():
    # CHAIN-006 is match_mode "all" over NR-001 + SE-003; SE-003 (SMB) also
    # supplies the Windows environment, so both-present builds it.
    ids = _chain_ids([_f("NR-001"), _f("SE-003", category=Category.SERVICE_EXPLOIT)])
    assert "CHAIN-006" in ids
    # NR-001 alone (no SMB, no Windows) builds neither 001 nor 006.
    assert _chain_ids([_f("NR-001")]) == set()
