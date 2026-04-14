"""Tests for finding rules."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from leetha.rules.registry import get_rule, get_all_rules, clear_rule_registry
from leetha.store.models import Host, Finding, FindingRule as FR, AlertSeverity
from leetha.evidence.models import Verdict


@pytest.fixture(autouse=True)
def reload_rules():
    clear_rule_registry()
    import importlib
    import leetha.rules.discovery
    import leetha.rules.drift
    import leetha.rules.anomaly
    import leetha.rules.randomization
    importlib.reload(leetha.rules.discovery)
    importlib.reload(leetha.rules.drift)
    importlib.reload(leetha.rules.anomaly)
    importlib.reload(leetha.rules.randomization)
    yield
    clear_rule_registry()


class TestRuleRegistry:
    def test_all_rules_registered(self):
        rules = get_all_rules()
        assert "new_host" in rules
        assert "low_certainty" in rules
        assert "identity_shift" in rules
        assert "addr_conflict" in rules
        # dhcp_anomaly and stale_source removed -- always returned None (dead code)
        assert "randomized_addr" in rules

    def test_unknown_rule(self):
        assert get_rule("nonexistent") is None


class TestNewHostRule:
    @pytest.mark.asyncio
    async def test_fires_for_new_host(self):
        store = MagicMock()
        store.hosts = AsyncMock()
        store.hosts.find_by_addr = AsyncMock(return_value=None)
        rule = get_rule("new_host")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", vendor="Cisco")
        result = await rule.evaluate(host, verdict, store)
        assert result is not None
        assert result.rule == FR.NEW_HOST
        assert "Cisco" in result.message

    @pytest.mark.asyncio
    async def test_does_not_fire_for_known_host(self):
        store = MagicMock()
        store.hosts = AsyncMock()
        existing = Host(hw_addr="aa:bb:cc:dd:ee:ff", disposition="known")
        store.hosts.find_by_addr = AsyncMock(return_value=existing)
        rule = get_rule("new_host")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", disposition="known")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        result = await rule.evaluate(host, verdict, store)
        assert result is None


class TestIdentityShiftRuleRegistry:
    """Basic registry tests for identity_shift (detailed tests in test_identity_shift.py)."""

    @pytest.mark.asyncio
    async def test_identity_shift_registered(self):
        rule_cls = get_rule("identity_shift")
        assert rule_cls is not None
        assert rule_cls.__name__ == "IdentityShiftRule"


class TestRandomizedAddrRule:
    @staticmethod
    def _store_with_existing_count(count: int):
        store = MagicMock()
        cursor = AsyncMock()
        cursor.fetchone = AsyncMock(return_value=(count,))
        store.connection.execute = AsyncMock(return_value=cursor)
        return store

    @pytest.mark.asyncio
    async def test_fires_for_randomized_mac(self):
        store = self._store_with_existing_count(0)
        rule = get_rule("randomized_addr")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", mac_randomized=True, real_hw_addr="11:22:33:44:55:66")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        result = await rule.evaluate(host, verdict, store)
        assert result is not None
        assert result.rule == FR.RANDOMIZED_ADDR
        assert "11:22:33:44:55:66" in result.message

    @pytest.mark.asyncio
    async def test_skips_when_finding_already_exists(self):
        store = self._store_with_existing_count(1)
        rule = get_rule("randomized_addr")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", mac_randomized=True, real_hw_addr="11:22:33:44:55:66")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        result = await rule.evaluate(host, verdict, store)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_fire_for_normal_mac(self):
        store = MagicMock()
        rule = get_rule("randomized_addr")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", mac_randomized=False)
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        result = await rule.evaluate(host, verdict, store)
        assert result is None


class TestLowCertaintyRule:
    @pytest.mark.asyncio
    async def test_fires_for_low_certainty(self):
        from leetha.rules import discovery
        discovery._LOW_CERT_LAST_FIRED.clear()
        store = MagicMock()
        # Mock the DB dedup query to return 0 existing findings
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=(0,))
        store.connection.execute = AsyncMock(return_value=mock_cursor)
        rule = get_rule("low_certainty")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", disposition="known")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", certainty=30)
        result = await rule.evaluate(host, verdict, store)
        assert result is not None
        assert result.rule == FR.LOW_CERTAINTY

    @pytest.mark.asyncio
    async def test_no_fire_for_high_certainty(self):
        store = MagicMock()
        rule = get_rule("low_certainty")()
        host = Host(hw_addr="aa:bb:cc:dd:ee:ff", disposition="known")
        verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", certainty=80)
        result = await rule.evaluate(host, verdict, store)
        assert result is None
