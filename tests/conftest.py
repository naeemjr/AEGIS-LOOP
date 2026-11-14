"""Shared test fixtures and helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROMPTS_DIR = PROJECT_ROOT / "configs" / "prompts"


def valid_finding(**overrides) -> dict:
    finding = {
        "title": "Stack buffer overflow via strcpy",
        "file": "examples/vuln_app.c",
        "lines": "12-18",
        "evidence": "strcpy copies user-controlled argv[1] into a 64-byte stack buffer.",
        "severity": "critical",
        "confidence": 0.9,
        "preconditions": "Attacker controls a command-line argument longer than 63 bytes.",
        "impact": "Stack corruption; crash or possible control-flow hijack.",
        "remediation": "Use a bounded copy such as snprintf(buf, sizeof buf, \"%s\", argv[1]).",
        "regression_test": "Run with a 256-byte argument under ASan; expect clean exit.",
        "detection_idea": "Static rule flagging strcpy into fixed-size stack buffers.",
        "limitations": "Static review only; exploitability not dynamically confirmed.",
        "safe_next_steps": "Patch, add the ASan regression test, re-run static analysis.",
    }
    finding.update(overrides)
    return finding


def valid_example_dict(**overrides) -> dict:
    example = {
        "task_type": "code_review",
        "instruction": "Review this code for security issues.",
        "input": "strcpy(buf, argv[1]);",
        "output": json.dumps([valid_finding()]),
        "source_id": "fixture-1",
        "human_review": {"reviewer": "alice", "status": "approved", "date": "2026-01-01"},
    }
    example.update(overrides)
    return example


@pytest.fixture()
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture()
def prompts_dir() -> Path:
    return PROMPTS_DIR
