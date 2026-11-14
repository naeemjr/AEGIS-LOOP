"""Ingest approved source files into data/raw/ with registry records."""

from __future__ import annotations

import shutil
from pathlib import Path

from . import project_root
from .registry import (
    default_data_registry_path,
    hash_file,
    load_data_registry,
    save_data_registry,
)
from .schemas import IngestRecord


def default_raw_dir() -> Path:
    return project_root() / "data" / "raw"


def _iter_files(source: Path) -> list[Path]:
    if source.is_dir():
        return sorted(p for p in source.iterdir() if p.is_file())
    return [source]


def ingest(
    sources: list[Path],
    approved_by: str,
    raw_dir: Path | None = None,
    registry_path: Path | None = None,
) -> list[IngestRecord]:
    """Copy approved files into the raw dir and record them in the registry."""
    raw_dir = raw_dir or default_raw_dir()
    raw_dir.mkdir(parents=True, exist_ok=True)
    registry = load_data_registry(registry_path)
    records: list[IngestRecord] = []
    for source in sources:
        for path in _iter_files(Path(source)):
            dest = raw_dir / path.name
            shutil.copy2(path, dest)
            record = IngestRecord(
                source_path=str(path.resolve()),
                dest_path=str(dest),
                sha256=hash_file(dest),
                approved_by=approved_by,
            )
            registry["ingest"].append(record.model_dump())
            records.append(record)
    save_data_registry(registry, registry_path)
    return records
