"""Parallel source-sync behavior."""
import asyncio

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
    # Unknown names are treated as single-file (bucket 0), must be
    # retained, and keep their relative input order. (There are currently
    # no git_multifile feeds, so the bucket-1 case is exercised by
    # test_order_single_file_feeds_before_multifile when one is added.)
    names = ["totally_unknown", "ieee_oui", "another_unknown"]
    ordered = _order_sources_small_first(names)
    assert sorted(ordered) == sorted(names)          # no drops/dupes
    # the two unknowns keep their relative input order
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
            for _ in range(5):
                await asyncio.sleep(0.005)
                yield {"event": "downloading", "source": name, "downloaded": 1}
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


async def test_merger_preserves_per_source_event_order(monkeypatch):
    from leetha.sync import sync_sources_concurrent
    import leetha.sync as sync_mod

    async def fake_gen(name):
        # Several ordered events per source, interleaved with awaits so
        # the scheduler can interleave sources.
        yield {"event": "start", "source": name}
        for i in range(5):
            await asyncio.sleep(0)
            yield {"event": "downloading", "source": name, "seq": i}
        yield {"event": "complete", "source": name, "entries": 0, "size": 0}

    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    per_source: dict[str, list] = {}
    async for ev in sync_sources_concurrent([f"s{i}" for i in range(4)], concurrency=4):
        per_source.setdefault(ev["source"], []).append(ev["event"])

    for name, events in per_source.items():
        assert events[0] == "start", f"{name} first event not start: {events}"
        assert events[-1] == "complete", f"{name} last event not complete: {events}"
        # downloading events must appear contiguously between start and complete
        assert events.count("downloading") == 5


async def test_sync_all_emits_envelope_and_no_source_index(monkeypatch):
    from leetha.sync import sync_all_with_progress
    import leetha.sync as sync_mod

    async def fake_gen(name):
        yield {"event": "start", "source": name}
        yield {"event": "complete", "source": name, "entries": 3, "size": 9}

    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    events = [ev async for ev in sync_all_with_progress()]
    kinds = [e["event"] for e in events]
    assert kinds[0] == "sync_start"
    assert kinds[-1] == "sync_complete"
    assert "source_index" not in kinds            # removed
    final = events[-1]
    assert final["succeeded"] >= 1
    assert final["failed"] == 0


async def test_sync_all_counts_mixed_success_and_failure(monkeypatch):
    from leetha.sync import sync_all_with_progress
    import leetha.sync as sync_mod

    # One source completes, one raises (merger converts to an error event).
    async def fake_gen(name):
        if "fail" in name:
            raise RuntimeError("nope")
            yield  # pragma: no cover
        yield {"event": "complete", "source": name, "entries": 1, "size": 1}

    # Force a known 2-source registry so counts are deterministic.
    # SourceRegistry is not exported at the leetha.sync module level
    # (sync_all_with_progress re-imports it locally), so patch it at its
    # real location.
    class _Src:
        def __init__(self, name): self.name = name
    monkeypatch.setattr(
        "leetha.sync.registry.SourceRegistry.list_sources",
        lambda self: [_Src("ok_one"), _Src("fail_two")],
    )
    monkeypatch.setattr(sync_mod, "sync_source_with_progress",
                        lambda n: fake_gen(n))

    events = [ev async for ev in sync_all_with_progress()]
    final = events[-1]
    assert final["event"] == "sync_complete"
    assert final["succeeded"] == 1
    assert final["failed"] == 1
    assert final["total_sources"] == 2


def test_cli_task_router_tracks_per_source():
    from leetha.sync import _CliSyncTracker

    t = _CliSyncTracker(["a", "b"])
    # start / downloading / parsing events return the source name (to refresh its bar)
    assert t.on_event({"event": "start", "source": "a"}) == "a"
    assert t.on_event({"event": "downloading", "source": "a",
                       "downloaded": 5, "total": 10}) == "a"
    res = t.on_event({"event": "complete", "source": "a",
                      "entries": 7, "size": 12})
    assert res == "a"
    assert t.succeeded == 1
    assert t.failed == 0
    assert t.total_entries == 7
    assert t.total_bytes == 12
    t.on_event({"event": "error", "source": "b", "error": "x"})
    assert t.failed == 1
    assert t.done == 2  # completed + errored


def test_cli_tracker_accumulates_and_defaults():
    from leetha.sync import _CliSyncTracker

    t = _CliSyncTracker(["a", "b", "c"])
    t.on_event({"event": "complete", "source": "a", "entries": 10, "size": 100})
    t.on_event({"event": "complete", "source": "b", "entries": 5, "size": 50})
    # a complete with no entries/size keys must default to 0 (no crash)
    t.on_event({"event": "complete", "source": "c"})
    assert t.succeeded == 3
    assert t.failed == 0
    assert t.done == 3
    assert t.total_entries == 15
    assert t.total_bytes == 150
    # unknown envelope events return None and don't touch counters
    assert t.on_event({"event": "sync_start", "total_sources": 3}) is None
    assert t.succeeded == 3 and t.done == 3
