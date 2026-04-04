import re
from leetha.patterns.index import PatternIndex


class TestPatternIndex:
    def setup_method(self):
        self.index = PatternIndex()
        self.index.add_pattern(
            category="ssh",
            pattern=re.compile(r"OpenSSH", re.IGNORECASE),
            metadata={"product": "OpenSSH", "vendor": "OpenBSD"},
        )
        self.index.add_pattern(
            category="http",
            pattern=re.compile(r"Apache", re.IGNORECASE),
            metadata={"product": "Apache", "vendor": "Apache Foundation"},
        )
        self.index.add_pattern(
            category="http",
            pattern=re.compile(r"nginx", re.IGNORECASE),
            metadata={"product": "nginx", "vendor": "F5"},
        )

    def test_search_with_category_hits(self):
        result = self.index.search("SSH-2.0-OpenSSH_9.2", category="ssh")
        assert result is not None
        assert result["product"] == "OpenSSH"

    def test_search_wrong_category_misses(self):
        result = self.index.search("SSH-2.0-OpenSSH_9.2", category="http")
        assert result is None

    def test_search_without_category_checks_all(self):
        result = self.index.search("Server: Apache/2.4.58")
        assert result is not None
        assert result["product"] == "Apache"

    def test_empty_index_returns_none(self):
        empty = PatternIndex()
        assert empty.search("anything") is None

    def test_category_count(self):
        assert self.index.category_count("ssh") == 1
        assert self.index.category_count("http") == 2
        assert self.index.category_count("ftp") == 0

    def test_categories_list(self):
        cats = self.index.categories()
        assert "ssh" in cats
        assert "http" in cats

    def test_search_returns_copy(self):
        """Returned dict should be a copy, not a reference to stored metadata."""
        result1 = self.index.search("OpenSSH", category="ssh")
        result1["product"] = "MODIFIED"
        result2 = self.index.search("OpenSSH", category="ssh")
        assert result2["product"] == "OpenSSH"

    def test_multiple_matches_returns_first(self):
        """When multiple patterns match, return the first one."""
        self.index.add_pattern(
            category="http",
            pattern=re.compile(r"Server:", re.IGNORECASE),
            metadata={"product": "GenericServer"},
        )
        result = self.index.search("Server: Apache/2.4", category="http")
        assert result["product"] == "Apache"  # Apache pattern added first
