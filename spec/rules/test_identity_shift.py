"""Tests for identity shift detection rule."""
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta, timezone
from leetha.store.models import Host, Finding, FindingRule as FR, AlertSeverity
from leetha.evidence.models import Evidence, Verdict


@pytest.fixture
def store():
    s = MagicMock()
    s.verdicts = AsyncMock()
    s.hosts = AsyncMock()
    return s


def _get_rule():
    """Get IdentityShiftRule with cooldown disabled for testing.

    The module-level _last_fired dict survives importlib.reload() from
    other test files, making cooldown state unpredictable. We set the
    cooldown to 0 on the live module so all evaluate() calls fire.
    """
    import leetha.rules.drift
    mod = sys.modules["leetha.rules.drift"]
    mod._last_fired.clear()
    mod._COOLDOWN_SECONDS = 0  # disable cooldown for tests
    return mod.IdentityShiftRule()


def _verdict(hw="aa:bb:cc:dd:ee:ff", category=None, vendor=None,
             platform=None, platform_version=None, certainty=80,
             evidence_count=5):
    chain = [Evidence(source=f"src{i}", method="exact", certainty=0.8)
             for i in range(evidence_count)]
    return Verdict(hw_addr=hw, category=category, vendor=vendor,
                   platform=platform, platform_version=platform_version,
                   certainty=certainty, evidence_chain=chain)


def _host(hw="aa:bb:cc:dd:ee:ff", age_seconds=120):
    return Host(hw_addr=hw,
                discovered_at=datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
                last_active=datetime.now(timezone.utc))


class TestIdentityShift:

    @pytest.mark.asyncio
    async def test_category_change_fires_critical(self, store):
        rule = _get_rule()
        old = _verdict(category="printer", vendor="HP", certainty=85)
        store.verdicts.find_by_addr = AsyncMock(return_value=old)
        result = await rule.evaluate(_host(), _verdict(category="laptop", vendor="Dell", certainty=80), store)
        assert result is not None
        assert result.rule == FR.IDENTITY_SHIFT
        assert result.severity == AlertSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_vendor_change_fires_critical(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="laptop", vendor="Apple", certainty=85))
        result = await rule.evaluate(_host(), _verdict(category="laptop", vendor="Samsung", certainty=80), store)
        assert result is not None
        assert result.severity == AlertSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_platform_change_fires_high(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="laptop", vendor="Dell", platform="Windows", certainty=80))
        result = await rule.evaluate(_host(), _verdict(category="laptop", vendor="Dell", platform="Linux", certainty=80), store)
        assert result is not None
        assert result.severity == AlertSeverity.HIGH

    @pytest.mark.asyncio
    async def test_version_change_fires_info(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="laptop", vendor="Dell", platform="Windows", platform_version="10", certainty=80))
        result = await rule.evaluate(_host(), _verdict(category="laptop", vendor="Dell", platform="Windows", platform_version="11", certainty=80), store)
        assert result is not None
        assert result.severity == AlertSeverity.INFO

    @pytest.mark.asyncio
    async def test_no_change_returns_none(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="laptop", vendor="Dell", platform="Windows", certainty=80))
        result = await rule.evaluate(_host(), _verdict(category="laptop", vendor="Dell", platform="Windows", certainty=85), store)
        assert result is None

    @pytest.mark.asyncio
    async def test_low_certainty_old_skips(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="printer", certainty=30))
        result = await rule.evaluate(_host(), _verdict(category="laptop", certainty=80), store)
        assert result is None

    @pytest.mark.asyncio
    async def test_low_certainty_new_skips(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="printer", certainty=80))
        result = await rule.evaluate(_host(), _verdict(category="laptop", certainty=30), store)
        assert result is None

    @pytest.mark.asyncio
    async def test_few_evidence_skips(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="printer", certainty=80, evidence_count=2))
        result = await rule.evaluate(_host(), _verdict(category="laptop", certainty=80), store)
        assert result is None

    @pytest.mark.asyncio
    async def test_grace_period_skips(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=_verdict(category="printer", certainty=80))
        result = await rule.evaluate(_host(age_seconds=30), _verdict(category="laptop", certainty=80), store)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_existing_verdict_skips(self, store):
        rule = _get_rule()
        store.verdicts.find_by_addr = AsyncMock(return_value=None)
        result = await rule.evaluate(_host(), _verdict(category="laptop", certainty=80), store)
        assert result is None
