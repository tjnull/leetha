"""Phase A.3 Task 19 — typed config schema for importers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal


FieldType = Literal["string", "int", "bool", "secret", "select"]


@dataclass
class ConfigField:
    name: str
    type: FieldType
    required: bool = False
    default: Any = None
    help: str = ""
    choices: list[str] | None = None  # only meaningful when type == "select"
    validator: Callable[[Any], None] | None = None


_PYTHON_TYPES: dict[FieldType, tuple[type, ...]] = {
    "string": (str,),
    "secret": (str,),
    "select": (str,),
    "int": (int,),
    "bool": (bool,),
}


def validate(schema: list[ConfigField], config: dict) -> None:
    """Raise ValueError on first violation, else return.

    - Required fields must be present and non-None
    - Each value must match the declared type
    - ``select`` fields must match one of the declared choices
    - Custom ``validator`` callables receive the value and may raise ValueError
    """
    for f in schema:
        present = f.name in config and config[f.name] is not None
        if not present:
            if f.required:
                raise ValueError(f"required field missing: {f.name!r}")
            continue
        value = config[f.name]
        expected_types = _PYTHON_TYPES.get(f.type)
        if expected_types is None:
            raise ValueError(f"unknown field type: {f.type!r}")
        # Python bools are instances of int — reject that overlap when we want int.
        if f.type == "int" and isinstance(value, bool):
            raise ValueError(f"field {f.name!r} must be int, not bool")
        if not isinstance(value, expected_types):
            raise ValueError(
                f"field {f.name!r} expected {f.type}, got {type(value).__name__}"
            )
        if f.type == "select":
            if not f.choices:
                raise ValueError(f"select field {f.name!r} has no choices declared")
            if value not in f.choices:
                raise ValueError(
                    f"field {f.name!r} must be one of {f.choices}, got {value!r}"
                )
        if f.validator is not None:
            f.validator(value)
