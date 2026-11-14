"""Content-addressed versioning for datasets and adapters.

Same content must always yield the same version string. Registries are plain
JSON files: ``data/registry.json`` for ingest + datasets and
``adapters/REGISTRY.json`` for adapter versions + the incumbent pointer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import project_root
from .schemas import AdapterRecord, EvalResult, utc_now


def hash_file(path: Path) -> str:
    """sha256 over raw file bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_obj(obj: Any) -> str:
    """sha256 over the canonical JSON serialization of an object."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def default_data_registry_path() -> Path:
    return project_root() / "data" / "registry.json"


def default_adapter_registry_path() -> Path:
    return project_root() / "adapters" / "REGISTRY.json"


def load_data_registry(path: Path | None = None) -> dict[str, Any]:
    path = path or default_data_registry_path()
    if not path.exists():
        return {"datasets": {}, "ingest": []}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_data_registry(registry: dict[str, Any], path: Path | None = None) -> None:
    path = path or default_data_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2, sort_keys=True)


def load_adapter_registry(path: Path | None = None) -> dict[str, Any]:
    path = path or default_adapter_registry_path()
    if not path.exists():
        return {"adapters": [], "incumbent": None}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_adapter_registry(registry: dict[str, Any], path: Path | None = None) -> None:
    path = path or default_adapter_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2, sort_keys=True)


def record_dataset(examples: list[dict[str, Any]], registry_path: Path | None = None) -> str:
    """Record a curated dataset and return its content-addressed version.

    Idempotent: re-recording identical content returns the same version
    without duplicating the entry.
    """
    canonical = [json.loads(json.dumps(e, default=str)) for e in examples]
    digest = hash_obj(canonical)
    version = f"ds-{digest[:12]}"
    registry = load_data_registry(registry_path)
    if version not in registry["datasets"]:
        registry["datasets"][version] = {
            "version": version,
            "count": len(canonical),
            "content_hash": digest,
            "created_at": utc_now(),
        }
        save_data_registry(registry, registry_path)
    return version


def get_dataset(version: str, registry_path: Path | None = None) -> dict[str, Any] | None:
    return load_data_registry(registry_path)["datasets"].get(version)


def record_adapter(
    *,
    base_model_id: str,
    base_model_revision: str,
    dataset_version: str,
    lora_config_hash: str,
    prompt_hashes: dict[str, str] | None = None,
    eval: EvalResult | None = None,
    registry_path: Path | None = None,
) -> AdapterRecord:
    """Allocate the next adapter version (v<N>) and record it."""
    registry = load_adapter_registry(registry_path)
    existing = [a["version"] for a in registry["adapters"]]
    version = max(existing, default=0) + 1
    record = AdapterRecord(
        version=version,
        path=f"adapters/v{version}",
        base_model_id=base_model_id,
        base_model_revision=base_model_revision,
        dataset_version=dataset_version,
        lora_config_hash=lora_config_hash,
        prompt_hashes=prompt_hashes or {},
        eval=eval,
        incumbent=False,
    )
    registry["adapters"].append(json.loads(record.model_dump_json()))
    save_adapter_registry(registry, registry_path)
    return record


def get_adapter(version: int, registry_path: Path | None = None) -> AdapterRecord | None:
    for entry in load_adapter_registry(registry_path)["adapters"]:
        if entry["version"] == version:
            return AdapterRecord(**entry)
    return None


def get_incumbent(registry_path: Path | None = None) -> AdapterRecord | None:
    registry = load_adapter_registry(registry_path)
    incumbent = registry.get("incumbent")
    if incumbent is None:
        return None
    return get_adapter(incumbent, registry_path)


def set_incumbent(version: int, registry_path: Path | None = None) -> None:
    registry = load_adapter_registry(registry_path)
    if get_adapter(version, registry_path) is None:
        raise KeyError(f"adapter v{version} not found in registry")
    registry["incumbent"] = version
    for entry in registry["adapters"]:
        entry["incumbent"] = entry["version"] == version
    save_adapter_registry(registry, registry_path)
