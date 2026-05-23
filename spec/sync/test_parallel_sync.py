"""Parallel source-sync behavior."""
import asyncio
import pytest

from leetha.sync import _order_sources_small_first


def test_order_single_file_feeds_before_multifile():
    from leetha.sync.registry import FeedCatalog
    cat = FeedCatalog()
    names = [f.key for f in cat.enumerate()]
    ordered = _order_sources_small_first(names)
    # same set, no drops/dupes
    assert sorted(ordered) == sorted(names)
    # every git_multifile feed comes after every single-file feed
    kinds = {f.key: f.kind for f in cat.enumerate()}
    first_multifile = next(
        (i for i, n in enumerate(ordered) if kinds[n] == "git_multifile"), len(ordered)
    )
    last_single = max(
        (i for i, n in enumerate(ordered) if kinds[n] != "git_multifile"), default=-1
    )
    assert last_single < first_multifile


def test_order_empty_list_returns_empty():
    assert _order_sources_small_first([]) == []


def test_order_unknown_names_retained_and_front_bucketed():
    # Unknown names are treated as single-file (bucket 0) and must be
    # retained; a known multifile feed must still sort last.
    names = ["huginn_mac_vendors", "totally_unknown", "another_unknown"]
    ordered = _order_sources_small_first(names)
    assert sorted(ordered) == sorted(names)          # no drops/dupes
    assert ordered[-1] == "huginn_mac_vendors"       # multifile last
    # the two unknowns keep their relative input order, ahead of multifile
    assert ordered.index("totally_unknown") < ordered.index("another_unknown")


def test_order_preserves_within_bucket_input_order():
    # Two known single-file feeds keep their input relative order.
    names = ["p0f", "ieee_oui"]
    assert _order_sources_small_first(names) == ["p0f", "ieee_oui"]
    assert _order_sources_small_first(["ieee_oui", "p0f"]) == ["ieee_oui", "p0f"]
