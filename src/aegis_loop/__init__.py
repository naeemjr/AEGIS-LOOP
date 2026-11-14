"""AEGIS-LOOP: versioned LoRA/QLoRA fine-tuning and multi-agent analysis
pipeline for DEFENSIVE security research."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

__version__ = "0.1.0"


def project_root() -> Path:
    """Resolve the project root (the directory containing configs/).

    Honours AEGIS_LOOP_ROOT, then walks up from the cwd looking for
    configs/base_model.yaml, then falls back to the cwd.
    """
    env = os.environ.get("AEGIS_LOOP_ROOT")
    if env:
        return Path(env).resolve()
    cwd = Path.cwd()
    for candidate in (cwd, *cwd.parents):
        if (candidate / "configs" / "base_model.yaml").exists():
            return candidate
    return cwd


def load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}
