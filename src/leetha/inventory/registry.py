"""Inventory importer registry (Phase A.3, Task 15)."""

from __future__ import annotations

_REGISTRY: dict[str, type] = {}


def register_importer(name: str):
    """Decorator that registers a BaseImporter subclass by canonical name."""

    def deco(cls):
        _REGISTRY[name] = cls
        cls._importer_name = name
        return cls

    return deco


def get_importer(name: str):
    return _REGISTRY.get(name)


def get_all_importers() -> dict[str, type]:
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Test helper — empties the registry."""
    _REGISTRY.clear()
