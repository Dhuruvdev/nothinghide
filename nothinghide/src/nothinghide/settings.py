"""Configuration file management for NothingHide."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict

from .platform import get_config_dir

CONFIG_FILE = "config.json"

@dataclass
class Settings:
    """User settings for NothingHide CLI."""
    
    output_format: str = "table"
    verbose: bool = False
    quiet: bool = False
    color: bool = True
    timeout: float = 15.0
    max_retries: int = 3
    parallel_requests: int = 5
    show_banner: bool = True
    default_export_dir: str = ""
    
    @classmethod
    def load(cls) -> "Settings":
        """Load settings from config file."""
        config_path = get_config_dir() / CONFIG_FILE
        
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    data = json.load(f)
                return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
            except Exception:
                pass
        
        return cls()
    
    def save(self) -> None:
        """Save settings to config file."""
        config_dir = get_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)
        
        config_path = config_dir / CONFIG_FILE
        
        with open(config_path, "w") as f:
            json.dump(asdict(self), f, indent=2)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return asdict(self)


def get_settings() -> Settings:
    """Get current settings (loads from file)."""
    return Settings.load()


def update_settings(**kwargs) -> Settings:
    """Update and save settings."""
    settings = Settings.load()
    
    for key, value in kwargs.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    
    settings.save()
    return settings


def reset_settings() -> Settings:
    """Reset settings to defaults."""
    settings = Settings()
    settings.save()
    return settings
