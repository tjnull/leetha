"""Processor registry with auto-discovery decorator."""
from __future__ import annotations

import logging
from typing import Type

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, Type] = {}


def register_processor(*protocols: str):
    """Decorator to register a processor class for one or more protocols."""
    def decorator(cls):
        for proto in protocols:
            if proto in _REGISTRY and _REGISTRY[proto] is not cls:
                logger.warning(
                    "Processor for protocol %s overwritten: %s -> %s",
                    proto, _REGISTRY[proto].__name__, cls.__name__,
                )
            _REGISTRY[proto] = cls
            logger.debug("Registered processor %s for protocol %s", cls.__name__, proto)
        cls._registered_protocols = list(protocols)
        return cls
    return decorator


def get_processor(protocol: str):
    """Look up the processor class registered for a protocol."""
    return _REGISTRY.get(protocol)


def get_all_processors() -> dict[str, Type]:
    """Return the full registry mapping."""
    return dict(_REGISTRY)


def clear_registry():
    """Clear all registrations (for testing)."""
    _REGISTRY.clear()
