"""Agent base class: prompt loading, output validation, one repair retry."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Union

from pydantic import ValidationError

from .. import project_root
from ..schemas import AnalysisPayload, Finding, Refusal

AgentOutput = Union[list[Finding], Refusal, AnalysisPayload]

REPAIR_SUFFIX = (
    "\n\nREPAIR: your previous output did not validate. Return ONLY valid JSON: "
    "either a list of finding objects each having exactly the 13 required fields "
    "(title, file, lines, evidence, severity, confidence, preconditions, impact, "
    "remediation, regression_test, detection_idea, limitations, safe_next_steps), "
    "or an object {\"findings\": [...], \"emulation_plans\": [...]}, "
    "or a refusal object {\"refusal\": true, \"reason\": ...}. No prose, no markdown fences."
)


def default_prompts_dir() -> Path:
    return project_root() / "configs" / "prompts"


def _normalize_finding_dict(item: dict) -> dict:
    """Coerce common real-model deviations into the Finding schema shape."""
    item = dict(item)
    # Small models often emit text fields as lists of strings; join them.
    for field in (
        "title", "file", "evidence", "preconditions", "impact", "remediation",
        "regression_test", "detection_idea", "limitations", "safe_next_steps",
    ):
        value = item.get(field)
        if isinstance(value, list):
            item[field] = "; ".join(str(part).strip() for part in value)
    lines = item.get("lines")
    if isinstance(lines, list):
        item["lines"] = ", ".join(str(part).strip() for part in lines)
    elif lines is not None and not isinstance(lines, str):
        item["lines"] = str(lines)
    confidence = item.get("confidence")
    if isinstance(confidence, str):
        try:
            item["confidence"] = float(confidence)
        except ValueError:
            item["confidence"] = 0.5
    return item


def parse_structured_output(raw: str) -> AgentOutput:
    """Parse a backend output into list[Finding], AnalysisPayload, or Refusal.

    Tolerates markdown fences and leading prose by decoding from the first
    JSON opening bracket/brace.
    """
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start = len(text)
    for char in ("[", "{"):
        idx = text.find(char)
        if idx != -1:
            start = min(start, idx)
    if start == len(text):
        raise ValueError("no JSON found in output")
    data, _ = json.JSONDecoder().raw_decode(text[start:])
    if isinstance(data, dict):
        if data.get("refusal") is True:
            return Refusal(**data)
        if "findings" in data or "emulation_plans" in data:
            if isinstance(data.get("findings"), list):
                data["findings"] = [
                    _normalize_finding_dict(f) if isinstance(f, dict) else f
                    for f in data["findings"]
                ]
            return AnalysisPayload(**data)
        raise ValueError("output object is neither a payload nor a refusal")
    if isinstance(data, list):
        return [
            Finding(**(_normalize_finding_dict(i) if isinstance(i, dict) else i))
            for i in data
        ]
    raise ValueError("output is neither a finding list nor a refusal object")


class AgentBase:
    """A named agent backed by an LLM backend and a versioned prompt file."""

    def __init__(self, name: str, backend, prompts_dir: Path | None = None) -> None:
        self.name = name
        self.backend = backend
        self.prompt_path = (prompts_dir or default_prompts_dir()) / f"{name}.md"
        self.system_prompt = self.prompt_path.read_text(encoding="utf-8")
        self.prompt_hash = hashlib.sha256(self.system_prompt.encode("utf-8")).hexdigest()

    def run(self, prompt: str) -> AgentOutput:
        """Run the agent; on validation failure retry once with a repair prompt."""
        raw = self.backend.generate(prompt, system_prompt=self.system_prompt)
        try:
            return parse_structured_output(raw)
        except (ValueError, ValidationError, json.JSONDecodeError):
            repaired = self.backend.generate(
                prompt + REPAIR_SUFFIX, system_prompt=self.system_prompt
            )
            return parse_structured_output(repaired)
