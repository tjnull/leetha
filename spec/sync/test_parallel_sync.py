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
