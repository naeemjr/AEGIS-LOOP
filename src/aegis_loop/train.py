"""QLoRA SFT training on the latest curated dataset.

Heavy ML dependencies (torch, transformers, peft, trl, datasets) are imported
lazily inside ``train()`` so the CLI and tests work without them. Config
loading and dataset-version resolution are import-safe and unit-testable.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any

from . import load_yaml, project_root
from .curate import resolve_latest_dataset
from .registry import default_adapter_registry_path, hash_obj, record_adapter
from .schemas import utc_now

ML_EXTRAS_MESSAGE = (
    "Training requires the ML extras, which are not installed. Install them "
    "with: pip install -e '.[ml]'  (torch, transformers, peft, trl, datasets, "
    "bitsandbytes, accelerate). Original import error: {error}"
)


class TrainingDependenciesError(ImportError):
    """Raised when torch/transformers/peft/trl/datasets are missing."""


def load_base_model_config(path: Path | None = None) -> dict[str, Any]:
    return load_yaml(path or project_root() / "configs" / "base_model.yaml")


def load_lora_config(path: Path | None = None) -> dict[str, Any]:
    return load_yaml(path or project_root() / "configs" / "lora.yaml")


def prompt_hashes(prompts_dir: Path | None = None) -> dict[str, str]:
    prompts_dir = prompts_dir or project_root() / "configs" / "prompts"
    hashes: dict[str, str] = {}
    for path in sorted(prompts_dir.glob("*.md")):
        hashes[path.stem] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def assert_base_frozen(model: Any) -> None:
    """Assert every non-LoRA parameter is frozen (requires_grad False)."""
    for name, param in model.named_parameters():
        if param.requires_grad and "lora" not in name.lower():
            raise AssertionError(f"base parameter is not frozen: {name}")


def train(
    smoke: bool = False,
    max_steps: int | None = None,
    max_length_override: int | None = None,
    runs_dir: Path | None = None,
) -> Path:
    """Run QLoRA SFT and save ONLY the adapter to adapters/v<N>/.

    Raises TrainingDependenciesError (an ImportError) when the ML stack is
    not installed.
    """
    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        raise TrainingDependenciesError(ML_EXTRAS_MESSAGE.format(error=exc)) from exc

    root = project_root()
    base_cfg = load_base_model_config()
    lora_cfg = load_lora_config()
    dataset_version, dataset_path = resolve_latest_dataset()
    lora_config_hash = hash_obj(lora_cfg)
    prompts = prompt_hashes()
    model_id = base_cfg["smoke_model_id"] if smoke else base_cfg["model_id"]
    revision = base_cfg.get("revision") or None

    # Allocate the adapter version up front so the save path is versioned.
    record = record_adapter(
        base_model_id=model_id,
        base_model_revision=base_cfg.get("revision") or "",
        dataset_version=dataset_version,
        lora_config_hash=lora_config_hash,
        prompt_hashes=prompts,
        registry_path=default_adapter_registry_path(),
    )
    adapter_dir = root / record.path
    adapter_dir.mkdir(parents=True, exist_ok=True)

    qlora = lora_cfg["qlora"]
    train_cfg = lora_cfg["training"]

    model_kwargs: dict[str, Any] = {"device_map": "auto"}
    target_modules = list(lora_cfg["lora"]["target_modules"])
    max_length = train_cfg["max_seq_len"]
    bf16 = train_cfg["bf16"]
    if smoke:
        # The smoke model (tiny-gpt2) is far too small for 4-bit quantization
        # to make sense, and its GPT-2 block names differ from the configured
        # Qwen-style projection names.
        model_kwargs["dtype"] = torch.float32
        target_modules = ["c_attn", "c_proj"]
        max_length = min(max_length, 512)
        bf16 = False
    else:
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=qlora["load_in_4bit"],
            bnb_4bit_quant_type=qlora["bnb_4bit_quant_type"],
            bnb_4bit_use_double_quant=qlora["bnb_4bit_use_double_quant"],
            bnb_4bit_compute_dtype=getattr(torch, qlora["bnb_4bit_compute_dtype"]),
        )
    if max_length_override is not None:
        max_length = max_length_override

    model = AutoModelForCausalLM.from_pretrained(
        model_id, revision=revision, **model_kwargs
    )
    if not smoke:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(
        model,
        LoraConfig(
            r=lora_cfg["lora"]["r"],
            lora_alpha=lora_cfg["lora"]["alpha"],
            lora_dropout=lora_cfg["lora"]["dropout"],
            target_modules=target_modules,
            bias=lora_cfg["lora"]["bias"],
            task_type=lora_cfg["lora"]["task_type"],
        ),
    )
    assert_base_frozen(model)

    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    dataset = load_dataset("json", data_files=str(dataset_path))["train"]

    def to_text(example: dict[str, Any]) -> dict[str, str]:
        return {
            "text": (
                f"### Instruction\n{example['instruction']}\n\n"
                f"### Input\n{example['input']}\n\n"
                f"### Response\n{example['output']}"
            )
        }

    dataset = dataset.map(to_text)
    args = SFTConfig(
        output_dir=str(adapter_dir),
        num_train_epochs=train_cfg["num_train_epochs"],
        learning_rate=train_cfg["learning_rate"],
        lr_scheduler_type=train_cfg["lr_scheduler_type"],
        bf16=bf16,
        per_device_train_batch_size=train_cfg["per_device_train_batch_size"],
        gradient_accumulation_steps=train_cfg["gradient_accumulation_steps"],
        logging_steps=train_cfg["logging_steps"],
        max_length=max_length,
        packing=False,
        save_strategy="no",
        report_to=[],
    )
    if max_steps is not None:
        args.max_steps = max_steps
    trainer = SFTTrainer(
        model=model,
        args=args,
        train_dataset=dataset,
        processing_class=tokenizer,
    )
    trainer.train()
    # Save the adapter only - never the merged base model.
    trainer.save_model(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))

    runs_dir = runs_dir or root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "adapter_version": record.version,
        "adapter_path": record.path,
        "base_model_id": model_id,
        "base_model_revision": revision or "",
        "dataset_version": dataset_version,
        "dataset_path": str(dataset_path),
        "lora_config_hash": lora_config_hash,
        "prompt_hashes": prompts,
        "created_at": utc_now(),
    }
    with open(runs_dir / f"train-v{record.version}.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return adapter_dir
