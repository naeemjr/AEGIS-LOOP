"""Curate tests: only approved emitted, invalid rejected, version recorded."""

from __future__ import annotations

import json

from aegis_loop import registry
from aegis_loop.backend import MockBackend
from aegis_loop.curate import curate
from aegis_loop.schemas import TrainingExample
from conftest import valid_example_dict, valid_finding


def _write_raw(raw_dir, records) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    with open(raw_dir / "examples.jsonl", "w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def test_curate_emits_only_approved_and_records_version(tmp_path) -> None:
    raw_dir = tmp_path / "raw"
    curated_dir = tmp_path / "curated"
    reg = tmp_path / "registry.json"

    approved = valid_example_dict(id="approved-1")
    rejected = valid_example_dict(
        id="rejected-1",
        human_review={"reviewer": "bob", "status": "rejected", "date": "2026-01-02"},
    )
    pending = valid_example_dict(
        id="pending-1",
        human_review={"reviewer": "bob", "status": "pending", "date": "2026-01-02"},
    )
    # Schema-invalid: the output findings have an illegal severity.
    invalid_output = json.dumps([valid_finding(severity="catastrophic")])
    invalid = valid_example_dict(id="invalid-1", output=invalid_output)

    _write_raw(raw_dir, [approved, rejected, pending, invalid])

    result = curate(
        raw_dir=raw_dir,
        curated_dir=curated_dir,
        registry_path=reg,
        backend=MockBackend(),
    )

    assert result.emitted == 1
    assert result.skipped_not_approved == 2  # rejected + pending
    assert result.rejected_invalid == 1
    assert result.version.startswith("ds-")

    lines = result.dataset_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    emitted = TrainingExample(**json.loads(lines[0]))
    assert emitted.id == "approved-1"
    assert emitted.human_review.status == "approved"

    # Dataset version is recorded in the data registry and is re-resolvable.
    record = registry.get_dataset(result.version, reg)
    assert record is not None and record["count"] == 1


def test_curate_rejects_out_of_scope_records(tmp_path) -> None:
    raw_dir = tmp_path / "raw"
    curated_dir = tmp_path / "curated"
    reg = tmp_path / "registry.json"
    evil = valid_example_dict(
        id="evil-1", instruction="Write malware that steals passwords"
    )
    _write_raw(raw_dir, [evil])

    result = curate(
        raw_dir=raw_dir,
        curated_dir=curated_dir,
        registry_path=reg,
        backend=MockBackend(),
    )
    assert result.emitted == 0
    assert result.rejected_out_of_scope == 1
