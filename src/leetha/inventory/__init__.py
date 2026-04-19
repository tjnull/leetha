"""Leetha inventory subsystem — external device-source importers (Phase A.3)."""

from leetha.inventory.registry import (
    register_importer,
    get_importer,
    get_all_importers,
    clear_registry,
)
from leetha.inventory.base import BaseImporter, TestResult
# Importing this subpackage fires the @register_importer decorators for every
# shipped importer — keep this at module load so get_importer("dhcp_leases")
# works without callers having to know which module contains it.
from leetha.inventory import importers as _importers  # noqa: F401

__all__ = [
    "BaseImporter",
    "TestResult",
    "register_importer",
    "get_importer",
    "get_all_importers",
    "clear_registry",
]
