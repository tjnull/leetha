"""Persist per-sensor interface selections across restarts."""
from __future__ import annotations

import json
from pathlib import Path


class SensorConfigStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    def _load(self) -> dict:
        if self._path.exists():
            return json.loads(self._path.read_text())
        return {}

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2))

    def save_interfaces(self, sensor_name: str, interfaces: list[str]) -> None:
        data = self._load()
        data[sensor_name] = {"interfaces": interfaces}
        self._save(data)

    def load_interfaces(self, sensor_name: str) -> list[str] | None:
        data = self._load()
        entry = data.get(sensor_name)
        if entry:
            return entry.get("interfaces")
        return None

    def delete(self, sensor_name: str) -> None:
        data = self._load()
        data.pop(sensor_name, None)
        self._save(data)
