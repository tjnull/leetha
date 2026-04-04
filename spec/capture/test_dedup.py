import time
from leetha.capture.dedup import TTLDedup


class TestTTLDedup:
    def test_first_seen_returns_false(self):
        cache = TTLDedup(max_entries=100, ttl_seconds=5.0)
        assert not cache.seen("aa:bb:cc:dd:ee:ff", 22)

    def test_second_seen_returns_true(self):
        cache = TTLDedup(max_entries=100, ttl_seconds=5.0)
        cache.seen("aa:bb:cc:dd:ee:ff", 22)
        assert cache.seen("aa:bb:cc:dd:ee:ff", 22)

    def test_different_key_independent(self):
        cache = TTLDedup(max_entries=100, ttl_seconds=5.0)
        cache.seen("aa:bb:cc:dd:ee:ff", 22)
        assert not cache.seen("aa:bb:cc:dd:ee:ff", 3306)

    def test_expired_entry_returns_false(self):
        cache = TTLDedup(max_entries=100, ttl_seconds=0.01)
        cache.seen("aa:bb:cc:dd:ee:ff", 22)
        time.sleep(0.02)
        assert not cache.seen("aa:bb:cc:dd:ee:ff", 22)

    def test_lru_eviction_at_max(self):
        cache = TTLDedup(max_entries=3, ttl_seconds=60.0)
        cache.seen("a", 1)
        cache.seen("b", 2)
        cache.seen("c", 3)
        # At capacity (3), order: [a, b, c]
        cache.seen("d", 4)  # evicts ("a", 1) — oldest; order: [b, c, d]
        assert len(cache) == 3
        assert not cache.seen("a", 1)  # was evicted, so first-seen; evicts b; order: [c, d, a]
        assert cache.seen("d", 4)  # still there
        assert cache.seen("c", 3)  # still there

    def test_len(self):
        cache = TTLDedup(max_entries=100, ttl_seconds=5.0)
        assert len(cache) == 0
        cache.seen("a", 1)
        assert len(cache) == 1
