"""Schema tests: Finding round-trip, required fields, enums, bounds."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis_loop.schemas import Finding, TrainingExample
from conftest import valid_example_dict, valid_finding


def test_finding_round_trip() -> None:
    finding = Finding(**valid_finding())
    restored = Finding(**finding.model_dump())
    assert restored == finding
    assert Finding(**finding.model_dump(mode="json")) == finding


def test_finding_missing_required_field_raises() -> None:
    data = valid_finding()
    del data["remediation"]
    with pytest.raises(ValidationError):
        Finding(**data)


def test_finding_severity_enum_enforced() -> None:
    with pytest.raises(ValidationError):
        Finding(**valid_finding(severity="severe"))
    for severity in ("critical", "high", "medium", "low", "info"):
        assert Finding(**valid_finding(severity=severity)).severity == severity


def test_finding_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Finding(**valid_finding(confidence=1.5))
    with pytest.raises(ValidationError):
        Finding(**valid_finding(confidence=-0.1))
    assert Finding(**valid_finding(confidence=0.0)).confidence == 0.0
    assert Finding(**valid_finding(confidence=1.0)).confidence == 1.0


def test_training_example_computes_content_hash() -> None:
    example = TrainingExample(**valid_example_dict())
    assert len(example.content_hash) == 64
    same = TrainingExample(**valid_example_dict())
    assert same.content_hash == example.content_hash


def test_training_example_rejects_invalid_output() -> None:
    with pytest.raises(ValidationError):
        TrainingExample(**valid_example_dict(output="not json"))
    with pytest.raises(ValidationError):
        TrainingExample(**valid_example_dict(output='{"unexpected": true}'))


def test_training_example_accepts_refusal_output() -> None:
    refusal = '{"refusal": true, "reason": "out of scope", "matched_patterns": ["malware_creation"], "safe_alternative": "ask for a defensive review"}'
    example = TrainingExample(**valid_example_dict(output=refusal))
    assert example.content_hash
