"""Fusion must not let stale/correlated fingerprint DBs overrule strong sources.

Regressions these pin (observed on live data):
  * authoritative IEEE OUI vendor must beat correlated Satori+Huginn guesses
    (Withings, not EyeFi);
  * duplicate same-source evidence must not double-count (a modern Windows
    DHCP signature stays "Windows", not "Windows 2000/XP");
  * "unknown" is a non-answer and never wins;
  * OUI device-type yields to behavioural evidence for MULTI-product vendors
    (Samsung TV stays smart_tv) but is kept for single-product vendors
    (Withings stays health_device).
"""

import pytest

from leetha.evidence.models import Evidence
from leetha.evidence.engine import VerdictEngine

eng = VerdictEngine()


def _e(source, certainty=0.9, **kw):
    return Evidence(source=source, method="exact", certainty=certainty, **kw)


def test_oui_vendor_beats_correlated_fingerprint_dbs():
    ev = [
        _e("oui", vendor="Withings", certainty=0.95),
        _e("satori_dhcp", vendor="EyeFi, Inc.", certainty=0.85),
        _e("huginn_device", vendor="EyeFi, Inc.", certainty=0.9),
    ]
    assert eng.compute("aa:bb:cc:00:00:01", ev).vendor == "Withings"


def test_duplicate_same_source_does_not_double_count():
    ev = [
        _e("dhcpv4_vendor", platform="Windows 2000/XP", certainty=0.85),
        _e("dhcpv4_vendor", platform="Windows 2000/XP", certainty=0.85),
        _e("huginn_device", platform="Windows", certainty=0.9),
    ]
    assert eng.compute("aa:bb:cc:00:00:02", ev).platform == "Windows"


def test_unknown_value_never_wins():
    ev = [
        _e("huginn_device", category="unknown", certainty=0.95),
        _e("oui", category="health_device", vendor="Withings", certainty=0.6),
    ]
    assert eng.compute("aa:bb:cc:00:00:03", ev).category == "health_device"


def test_oui_category_yields_to_behavioral_for_multiproduct_vendor():
    # Samsung makes phones AND TVs — OUI "phone" must yield to SSDP smart_tv.
    ev = [
        _e("oui", vendor="Samsung Electronics Co.,Ltd", category="phone", certainty=0.95),
        _e("ssdp_server", category="smart_tv", certainty=0.85),
    ]
    assert eng.compute("aa:bb:cc:00:00:04", ev).category == "smart_tv"


def test_oui_category_kept_for_single_product_vendor():
    # Withings only makes health devices — OUI category beats a bogus DHCP guess.
    ev = [
        _e("oui", vendor="Withings", category="health_device", certainty=0.95),
        _e("dhcp", category="router", certainty=0.75),
    ]
    assert eng.compute("aa:bb:cc:00:00:05", ev).category == "health_device"
