"""Data curator agent: structure raw approved records into TrainingExample drafts.

With MockBackend this is a deterministic pass-through of pre-structured
examples. With a real backend the raw record is embedded in a prompt and the
model returns the structured draft.
"""

from __future__ import annotations

import json
from typing import Any

from .base import AgentBase


class DataCuratorAgent(AgentBase):
    def __init__(self, backend, prompts_dir=None) -> None:
        super().__init__("data_curator", backend, prompts_dir)

    def structure(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        """Return a TrainingExample-shaped draft dict for a raw record."""
        from ..backend import MockBackend  # local import to avoid a cycle

        if isinstance(self.backend, MockBackend):
            draft = dict(raw_record)
        else:
            prompt = (
                "Structure the following raw record into a defensive-security "
                "training example. Output ONLY the JSON object.\n\n"
                f"RAW_RECORD: {json.dumps(raw_record)} END_RAW_RECORD"
            )
            raw = self.backend.generate(prompt, system_prompt=self.system_prompt)
            text = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
            draft = json.loads(text)

        # Normalize: fill defaults the schema expects.
        draft.setdefault("task_type", "code_review")
        draft.setdefault("source_id", "unknown")
        draft.setdefault(
            "human_review", {"reviewer": "unassigned", "status": "pending", "date": ""}
        )
        return draft
