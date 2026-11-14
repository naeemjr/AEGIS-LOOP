"""Pydantic v2 schemas shared across the AEGIS-LOOP pipeline."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]

# Lower number = more severe; used for ordering findings.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

TaskType = Literal[
    "code_review",
    "threat_model",
    "remediation",
    "detection",
    "report",
    "lab_recon",
    "ctf_writeup",
    "attack_emulation",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Reference(BaseModel):
    """A live, read-only public reference attached by the research agent.

    Sources are public, key-less APIs (NVD CVE, MITRE ATT&CK). Only short
    keyword queries and ATT&CK technique IDs are ever sent remotely - never
    target code or file contents.
    """

    source: Literal["nvd", "attack"]
    id: str
    title: str
    url: str
    severity: str | None = None
    snippet: str = ""


class Finding(BaseModel):
    """A single defensive security finding."""

    title: str
    file: str
    lines: str  # e.g. "12-18"
    evidence: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    preconditions: str
    impact: str
    remediation: str
    regression_test: str
    detection_idea: str
    limitations: str
    safe_next_steps: str
    references: list[Reference] = Field(default_factory=list)


class Refusal(BaseModel):
    """Structured refusal for out-of-scope (offensive) requests."""

    refusal: bool = True
    reason: str
    matched_patterns: list[str] = Field(default_factory=list)
    safe_alternative: str = ""


class EmulationPlan(BaseModel):
    """Purple-team ATT&CK emulation plan for an authorized lab environment."""

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    objective: str
    lab_preconditions: str
    procedure: list[str]
    detection_opportunities: list[str]
    cleanup: list[str]
    safety_notes: str
    references: list[Reference] = Field(default_factory=list)


class AnalysisPayload(BaseModel):
    """Structured agent output: findings plus optional emulation plans."""

    findings: list[Finding] = Field(default_factory=list)
    emulation_plans: list[EmulationPlan] = Field(default_factory=list)


class HumanReview(BaseModel):
    reviewer: str
    status: Literal["pending", "approved", "rejected"]
    date: str


class TrainingExample(BaseModel):
    """One curated SFT example for a defensive task."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_type: TaskType
    instruction: str
    input: str
    output: str  # JSON string: list[Finding] or a refusal object
    source_id: str
    human_review: HumanReview
    content_hash: str = ""

    @field_validator("output")
    @classmethod
    def output_must_be_findings_or_refusal(cls, value: str) -> str:
        try:
            data = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"output is not valid JSON: {exc}") from exc
        if isinstance(data, dict) and data.get("refusal") is True:
            Refusal(**data)
            return value
        if isinstance(data, dict) and ("findings" in data or "emulation_plans" in data):
            AnalysisPayload(**data)
            return value
        if isinstance(data, list):
            for item in data:
                Finding(**item)
            return value
        raise ValueError("output must be a JSON list of findings or a refusal object")

    @model_validator(mode="after")
    def compute_content_hash(self) -> "TrainingExample":
        payload = self.instruction + self.input + self.output
        self.content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self


class IngestRecord(BaseModel):
    source_path: str
    dest_path: str
    sha256: str
    ingested_at: str = Field(default_factory=utc_now)
    approved_by: str


class EvalScores(BaseModel):
    schema_validity: float = Field(ge=0.0, le=1.0)
    severity_calibration: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    remediation_quality: float = Field(ge=0.0, le=1.0)
    composite: float = Field(ge=0.0, le=1.0)


class EvalResult(BaseModel):
    adapter_version: str
    dataset_version: str
    benchmark_hash: str
    scores: EvalScores
    critical_policy_failures: int = 0
    per_example: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)


class AdapterRecord(BaseModel):
    version: int  # v<N>
    path: str
    base_model_id: str
    base_model_revision: str
    dataset_version: str
    lora_config_hash: str
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    eval: EvalResult | None = None
    incumbent: bool = False
    created_at: str = Field(default_factory=utc_now)
