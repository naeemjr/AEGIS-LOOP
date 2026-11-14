"""Curate raw approved records into validated TrainingExample JSONL.

Only examples with human_review.status == "approved" are emitted. Each run
writes data/curated/dataset-<version>.jsonl and records the content-addressed
dataset version in the data registry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from . import project_root
from .agents.data_curator import DataCuratorAgent
from .backend import get_backend
from .policy import check_scope
from .registry import default_data_registry_path, record_dataset
from .schemas import TrainingExample


def default_raw_dir() -> Path:
    return project_root() / "data" / "raw"


def default_curated_dir() -> Path:
    return project_root() / "data" / "curated"


@dataclass
class CurateResult:
    version: str
    dataset_path: Path
    emitted: int = 0
    skipped_not_approved: int = 0
    rejected_invalid: int = 0
    rejected_out_of_scope: int = 0
    rejected_ids: list[str] = field(default_factory=list)


def _iter_raw_records(raw_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(raw_dir.glob("*.jsonl")):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def curate(
    raw_dir: Path | None = None,
    curated_dir: Path | None = None,
    registry_path: Path | None = None,
    backend=None,
) -> CurateResult:
    raw_dir = raw_dir or default_raw_dir()
    curated_dir = curated_dir or default_curated_dir()
    curated_dir.mkdir(parents=True, exist_ok=True)
    backend = backend or get_backend()
    curator = DataCuratorAgent(backend)

    accepted: list[TrainingExample] = []
    result = CurateResult(version="", dataset_path=Path())
    for record in _iter_raw_records(raw_dir):
        record_id = str(record.get("id", record.get("source_id", "unknown")))
        # Policy gate: never curate out-of-scope content into training data.
        scope = check_scope(json.dumps(record))
        if not scope.allowed:
            result.rejected_out_of_scope += 1
            result.rejected_ids.append(record_id)
            continue
        try:
            draft = curator.structure(record)
            example = TrainingExample(**draft)
        except (ValidationError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            result.rejected_invalid += 1
            result.rejected_ids.append(record_id)
            continue
        if example.human_review.status != "approved":
            result.skipped_not_approved += 1
            result.rejected_ids.append(record_id)
            continue
        accepted.append(example)

    version = record_dataset(
        [json.loads(ex.model_dump_json()) for ex in accepted],
        registry_path or default_data_registry_path(),
    )
    dataset_path = curated_dir / f"dataset-{version}.jsonl"
    with open(dataset_path, "w", encoding="utf-8") as fh:
        for example in accepted:
            fh.write(example.model_dump_json() + "\n")

    result.version = version
    result.dataset_path = dataset_path
    result.emitted = len(accepted)
    return result


def resolve_latest_dataset(
    registry_path: Path | None = None,
    curated_dir: Path | None = None,
) -> tuple[str, Path]:
    """Return (version, path) of the most recently recorded curated dataset."""
    from .registry import load_data_registry

    registry = load_data_registry(registry_path)
    datasets = registry.get("datasets", {})
    if not datasets:
        raise FileNotFoundError("no curated datasets recorded; run `aegis-loop curate` first")
    version = max(datasets, key=lambda v: datasets[v]["created_at"])
    curated_dir = curated_dir or default_curated_dir()
    path = curated_dir / f"dataset-{version}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"curated dataset file missing: {path}")
    return version, path
