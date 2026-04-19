"""Base classes for inventory importers (Phase A.3, Task 15)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass
class TestResult:
    ok: bool
    message: str
    device_count: int | None = None


@dataclass
class ImportedDevice:
    """A single record yielded by an importer's sync() iterator."""
    mac: str
    ip: str | None = None
    hostname: str | None = None
    source: str = ""
    certainty: float = 0.5
    metadata: dict | None = None


class BaseImporter(ABC):
    """Every inventory importer subclasses this and is registered via ``@register_importer``."""

    # Populated by @register_importer
    _importer_name: str = ""

    @property
    def name(self) -> str:
        return self._importer_name

    @abstractmethod
    async def sync(self) -> AsyncIterator[ImportedDevice]:
        """Yield ImportedDevice records from the external source."""
        raise NotImplementedError

    async def test_connection(self) -> TestResult:
        return TestResult(ok=False, message="test_connection not implemented")

    def configure(self, config: dict) -> None:
        """Stash config on the instance. Subclasses can override for validation."""
        self._config = config

    @classmethod
    def config_schema(cls) -> list:
        """Return a list of ConfigField describing the importer's options."""
        return []
