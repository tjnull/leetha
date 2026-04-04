from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
def _real_home() -> Path:
    """Return the invoking user's home directory, even under sudo."""
    from leetha.platform import get_home_dir
    return get_home_dir()

from leetha.capture.interfaces import InterfaceConfig


@dataclass
class LeethaConfig:
    """Application configuration."""

    # Data directories
    cache_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("LEETHA_CACHE_DIR", _real_home() / ".cache" / "leetha")
    ))
    data_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("LEETHA_DATA_DIR", _real_home() / ".local" / "share" / "leetha")
    ))

    # Database
    db_path: Path = field(init=False)

    # Network — multi-interface
    interfaces: list[InterfaceConfig] = field(default_factory=list)
    bpf_filter: str = ""

    # Performance
    worker_count: int = 4
    db_batch_size: int = 50
    db_flush_interval: float = 0.1

    # Web UI
    web_host: str = "0.0.0.0"
    web_port: int = 8080

    # Sync
    sync_interval_days: int = 7

    # Active probing
    probe_enabled: bool = False
    probe_max_concurrent: int = 10
    probe_cooldown_seconds: int = 3600

    @property
    def interface(self) -> str | None:
        """Deprecated: returns first interface name for backward compat."""
        return self.interfaces[0].name if self.interfaces else None

    def __post_init__(self):
        self.db_path = self.data_dir / "leetha.db"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # When running under sudo, fix ownership so the real user
        # owns these directories and the DB file.
        from leetha.platform import fix_ownership
        fix_ownership(self.cache_dir)
        fix_ownership(self.data_dir)
        # Fix parent dirs too (.cache, .local, .local/share)
        for d in (self.cache_dir, self.data_dir):
            for parent in d.parents:
                if parent == Path.home() or parent == Path("/"):
                    break
                fix_ownership(parent)


# Global config instance
_config: LeethaConfig | None = None


def get_config() -> LeethaConfig:
    global _config
    if _config is None:
        _config = LeethaConfig()
    return _config


def set_config(config: LeethaConfig) -> None:
    global _config
    _config = config


_SETTINGS_FILE = "settings.json"

_PERSISTABLE_FIELDS = [
    "web_host", "web_port", "worker_count",
    "db_batch_size", "db_flush_interval", "sync_interval_days",
    "bpf_filter", "probe_enabled", "probe_max_concurrent",
    "probe_cooldown_seconds",
]


def save_config(config: LeethaConfig) -> None:
    """Persist user-configurable settings to settings.json in data_dir."""
    import json
    data = {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}
    settings_path = config.data_dir / _SETTINGS_FILE
    settings_path.write_text(json.dumps(data, indent=2))


def load_config(
    data_dir: Path | None = None,
    cache_dir: Path | None = None,
) -> LeethaConfig:
    """Load config, overlaying any saved settings.json values."""
    import json
    kwargs = {}
    if data_dir:
        kwargs["data_dir"] = data_dir
    if cache_dir:
        kwargs["cache_dir"] = cache_dir
    config = LeethaConfig(**kwargs)
    settings_path = config.data_dir / _SETTINGS_FILE
    if settings_path.exists():
        saved = json.loads(settings_path.read_text())
        for key, value in saved.items():
            if key in _PERSISTABLE_FIELDS and hasattr(config, key):
                setattr(config, key, value)
    return config
