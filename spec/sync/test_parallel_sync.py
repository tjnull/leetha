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


async def _fake_source(name, events):
    """Yield a canned event list for one source with small awaits."""
    for ev in events:
        await asyncio.sleep(0)
        yield {**ev, "source": name}


async def test_merger_surfaces_all_source_events(monkeypatch):
    from leetha.sync import sync_sources_concurrent
    import leetha.sync as sync_mod

    plan = {
        "a": [{"event": "start"}, {"event": "complete", "entries": 1, "size": 1}],
        "b": [{"event": "start"}, {"event": "complete", "entries": 2, "size": 2}],
        "c": [{"event": "start"}, {"event": "error", "error": "boom"}],
    }

    def fake(name):
        return _fake_source(name, plan[name])

    monkeypatch.setattr(sync_mod, "sync_source_with_progress", fake)

    seen = {}
    async for ev in sync_sources_concurrent(list(plan), concurrency=2):
        seen.setdefault(ev["source"], []).append(ev["event"])

    assert set(seen) == {"a", "b", "c"}
    assert seen["a"][-1] == "complete"
    assert seen["c"][-1] == "error"


async def test_merger_respects_concurrency_bound(monkeypatch):
    from leetha.sync import sync_sources_concurrent
    import leetha.sync as sync_mod

    active = 0
    peak = 0

    async def fake_gen(name):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.02)
            yield {"event": "complete", "source": name, "entries": 0, "size": 0}
        finally:
            active -= 1

    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    names = [f"s{i}" for i in range(12)]
    async for _ in sync_sources_concurrent(names, concurrency=3):
        pass
    assert peak <= 3


async def test_merger_isolates_worker_exceptions(monkeypatch):
    from leetha.sync import sync_sources_concurrent
    import leetha.sync as sync_mod

    async def fake_gen(name):
        if name == "bad":
            raise RuntimeError("kaboom")
            yield  # pragma: no cover
        yield {"event": "complete", "source": name, "entries": 0, "size": 0}

    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    results = {}
    async for ev in sync_sources_concurrent(["bad", "good"], concurrency=2):
        results[ev["source"]] = ev["event"]
    assert results["bad"] == "error"
    assert results["good"] == "complete"


async def test_merger_clean_early_close(monkeypatch):
    from leetha.sync import sync_sources_concurrent
    import leetha.sync as sync_mod

    async def fake_gen(name):
        for _ in range(50):
            await asyncio.sleep(0.01)
            yield {"event": "downloading", "source": name, "downloaded": 1}

    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    gen = sync_sources_concurrent([f"s{i}" for i in range(5)], concurrency=5)
    first = await gen.__anext__()
    assert first["event"] == "downloading"
    await gen.aclose()  # must not raise / leave orphan tasks
