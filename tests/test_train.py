"""Train-module logic that is unit-testable without the heavy ML deps."""

from __future__ import annotations

import json

import pytest

from aegis_loop import registry
from aegis_loop.train import (
    TrainingDependenciesError,
    load_base_model_config,
    load_lora_config,
    train,
)
from aegis_loop.curate import resolve_latest_dataset
from conftest import PROJECT_ROOT, valid_example_dict


def test_config_loading() -> None:
    base = load_base_model_config(PROJECT_ROOT / "configs" / "base_model.yaml")
    assert base["model_id"] == "Qwen/Qwen2.5-7B-Instruct"
    assert "revision" in base
    assert base["smoke_model_id"] == "sshleifer/tiny-gpt2"

    lora = load_lora_config(PROJECT_ROOT / "configs" / "lora.yaml")
    assert lora["lora"]["r"] == 16
    assert lora["lora"]["alpha"] == 32
    assert lora["qlora"]["bnb_4bit_quant_type"] == "nf4"
    assert lora["training"]["learning_rate"] == 2.0e-4
    assert lora["training"]["max_seq_len"] == 4096


def test_resolve_latest_dataset(tmp_path) -> None:
    reg = tmp_path / "registry.json"
    curated_dir = tmp_path / "curated"
    curated_dir.mkdir()

    with pytest.raises(FileNotFoundError):
        resolve_latest_dataset(reg, curated_dir)

    v1 = registry.record_dataset([valid_example_dict(id="a")], reg)
    (curated_dir / f"dataset-{v1}.jsonl").write_text(
        json.dumps(valid_example_dict(id="a")) + "\n"
    )
    v2 = registry.record_dataset([valid_example_dict(id="b")], reg)
    (curated_dir / f"dataset-{v2}.jsonl").write_text(
        json.dumps(valid_example_dict(id="b")) + "\n"
    )

    version, path = resolve_latest_dataset(reg, curated_dir)
    assert version in {v1, v2}
    assert path.exists()
    assert path.name == f"dataset-{version}.jsonl"


def test_train_fails_gracefully_without_ml_deps() -> None:
    pytest.importorskip("sys")
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        import peft  # noqa: F401
        import trl  # noqa: F401
        import datasets  # noqa: F401

        pytest.skip("ML stack unexpectedly installed")
    except ImportError:
        pass
    with pytest.raises(TrainingDependenciesError) as excinfo:
        train()
    message = str(excinfo.value)
    assert "pip install" in message
    assert "ml" in message.lower()
