"""Validator must not flag locally-administered / randomized MACs.

Randomized and locally-administered MACs are never in the IEEE OUI registry
by design, so reporting them as "OUI coverage missing" or "manufacturer
mismatch" is always a false positive. This works off the address bits, so it
holds even when the stored is_randomized_mac flag wasn't populated.
"""

import pytest

from leetha.analysis.validator import _is_locally_administered, _skip_for_oui


class _Dev:
    def __init__(self, mac, is_randomized_mac=False, manufacturer=None):
        self.mac = mac
        self.is_randomized_mac = is_randomized_mac
        self.manufacturer = manufacturer


def test_locally_administered_bit_detection():
    # 0xFA -> ...1010 -> U/L bit set;  0x4A -> ...1010 -> set
    assert _is_locally_administered("fa:7c:26:59:f1:09") is True
    assert _is_locally_administered("4a:a7:a8:39:3a:71") is True
    # 0xA0 -> 1010_0000 -> U/L bit (0x02) clear → universally administered
    assert _is_locally_administered("a0:36:bc:ac:ab:ab") is False
    # Real Intel OUI (0x00) clear
    assert _is_locally_administered("00:1b:21:00:00:01") is False


def test_skip_for_oui_covers_laa_even_without_flag():
    # Flag not set, but the address itself is locally administered → skip.
    assert _skip_for_oui(_Dev("fa:7c:26:59:f1:09", is_randomized_mac=False)) is True
    # Universally administered, not randomized → checked.
    assert _skip_for_oui(_Dev("a0:36:bc:ac:ab:ab", is_randomized_mac=False)) is False
    # Explicit randomized flag → skip regardless of bits.
    assert _skip_for_oui(_Dev("a0:36:bc:ac:ab:ab", is_randomized_mac=True)) is True


def test_malformed_mac_does_not_crash():
    assert _is_locally_administered("") is False
    assert _is_locally_administered("zz") is False
