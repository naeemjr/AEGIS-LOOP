"""Registry tests: content-addressed versions, adapter records, incumbent."""

from __future__ import annotations

from aegis_loop import registry
from conftest import valid_example_dict


def test_same_content_same_version(tmp_path) -> None:
    reg = tmp_path / "registry.json"
    examples = [valid_example_dict(id="ex-1")]
    v1 = registry.record_dataset(examples, reg)
    v2 = registry.record_dataset([dict(e) for e in examples], reg)
    assert v1 == v2
    assert v1.startswith("ds-")


def test_changed_content_new_version(tmp_path) -> None:
    reg = tmp_path / "registry.json"
    v1 = registry.record_dataset([valid_example_dict(id="ex-1")], reg)
    v2 = registry.record_dataset([valid_example_dict(id="ex-2")], reg)
    assert v1 != v2


def test_dataset_record_retrievable(tmp_path) -> None:
    reg = tmp_path / "registry.json"
    version = registry.record_dataset([valid_example_dict(id="ex-1")], reg)
    record = registry.get_dataset(version, reg)
    assert record is not None
    assert record["version"] == version
    assert record["count"] == 1


def test_adapter_records_and_incumbent(tmp_path) -> None:
    reg = tmp_path / "REGISTRY.json"
    first = registry.record_adapter(
        base_model_id="Qwen/Qwen2.5-7B-Instruct",
        base_model_revision="",
        dataset_version="ds-aaa",
        lora_config_hash="hash1",
        registry_path=reg,
    )
    second = registry.record_adapter(
        base_model_id="Qwen/Qwen2.5-7B-Instruct",
        base_model_revision="",
        dataset_version="ds-bbb",
        lora_config_hash="hash2",
        registry_path=reg,
    )
    assert (first.version, second.version) == (1, 2)
    assert first.path == "adapters/v1"
    assert second.path == "adapters/v2"

    fetched = registry.get_adapter(2, reg)
    assert fetched is not None and fetched.dataset_version == "ds-bbb"

    assert registry.get_incumbent(reg) is None
    registry.set_incumbent(2, reg)
    incumbent = registry.get_incumbent(reg)
    assert incumbent is not None and incumbent.version == 2 and incumbent.incumbent
    assert registry.get_adapter(1, reg).incumbent is False


def test_hash_file_stable(tmp_path) -> None:
    path = tmp_path / "f.txt"
    path.write_text("hello")
    assert registry.hash_file(path) == registry.hash_file(path)
    path.write_text("hello!")
    before = registry.hash_file(path)
    path.write_text("hello?")
    assert registry.hash_file(path) != before
