"""Category-indexed pattern registry for O(1) category lookup.

Instead of scanning all 2000+ patterns linearly, callers provide a
category hint (derived from port/protocol) to narrow the search to
only relevant patterns.
"""
from __future__ import annotations

import re
from typing import Optional


class PatternIndex:
    """Category-indexed pattern store for fast banner matching."""

    def __init__(self):
        self._by_category: dict[str, list[tuple[re.Pattern, dict]]] = {}

    def add_pattern(self, category: str, pattern: re.Pattern, metadata: dict) -> None:
        """Register a compiled pattern under a category."""
        self._by_category.setdefault(category, []).append((pattern, metadata))

    def category_count(self, category: str) -> int:
        """Return number of patterns in a category."""
        return len(self._by_category.get(category, []))

    def categories(self) -> list[str]:
        """Return all category names."""
        return list(self._by_category.keys())

    def search(self, text: str, category: str | None = None) -> Optional[dict]:
        """Search patterns, optionally narrowed to a category.

        If category is provided, only check patterns in that category (fast path).
        Otherwise check all categories (slow fallback).
        """
        if category:
            return self._search_category(text, category)

        for cat_patterns in self._by_category.values():
            result = self._match_list(text, cat_patterns)
            if result is not None:
                return result
        return None

    def _search_category(self, text: str, category: str) -> Optional[dict]:
        patterns = self._by_category.get(category)
        if not patterns:
            return None
        return self._match_list(text, patterns)

    @staticmethod
    def _match_list(text: str, patterns: list[tuple[re.Pattern, dict]]) -> Optional[dict]:
        for regex, metadata in patterns:
            if regex.search(text):
                return dict(metadata)
        return None
