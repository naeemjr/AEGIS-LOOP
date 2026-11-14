"""Coordinator: classify inputs, dispatch specialist agents, merge outputs.

The coordinator always dispatches the defensive agents (code research,
threat research). It additionally dispatches the red team research agent when
the request is lab-scoped offensive work: either ``mode="redteam"`` was
requested explicitly, or ``mode="auto"`` and the policy gate determined the
request is lab-scoped (``lab_scope=True``).
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError
import json

from ..schemas import (
    AnalysisPayload,
    EmulationPlan,
    Finding,
    Refusal,
    SEVERITY_ORDER,
)
from .base import AgentBase, AgentOutput, default_prompts_dir
from .code_research import CodeResearchAgent
from .red_team import RedTeamAgent
from .threat_research import ThreatResearchAgent

_CODE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".py", ".go", ".rs", ".js", ".ts", ".java"}
_CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env"}

VALID_MODES = ("auto", "defensive", "redteam")


class CoordinatorResult(BaseModel):
    target: str
    category: str
    mode: str = "auto"
    lab_scope: bool = False
    findings: list[Finding] = Field(default_factory=list)
    emulation_plans: list[EmulationPlan] = Field(default_factory=list)
    refusals: list[Refusal] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    agents_run: list[str] = Field(default_factory=list)


def classify(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in _CODE_SUFFIXES:
        return "code"
    if suffix in _CONFIG_SUFFIXES:
        return "config"
    return "document"


def _normalize_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def _parse_lines(spec: str) -> list[tuple[int, int]]:
    """Parse a lines spec like "12-18" or "5, 9-11" into (start, end) ranges."""
    ranges: list[tuple[int, int]] = []
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else start
            ranges.append((start, end))
    return ranges


def _lines_overlap(a: str, b: str) -> bool:
    for start_a, end_a in _parse_lines(a):
        for start_b, end_b in _parse_lines(b):
            if start_a <= end_b and start_b <= end_a:
                return True
    return False


def _same_finding(a: Finding, b: Finding) -> bool:
    return (
        a.file == b.file
        and _normalize_title(a.title) == _normalize_title(b.title)
        and _lines_overlap(a.lines, b.lines)
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates: same file + overlapping lines + same normalized title.

    Keeps the higher-confidence duplicate.
    """
    kept: list[Finding] = []
    for finding in sorted(findings, key=lambda f: -f.confidence):
        if not any(_same_finding(finding, other) for other in kept):
            kept.append(finding)
    return kept


def dedupe_plans(plans: list[EmulationPlan]) -> list[EmulationPlan]:
    """Drop duplicate plans by ATT&CK technique id, keeping the first seen."""
    seen: dict[str, EmulationPlan] = {}
    for plan in plans:
        seen.setdefault(plan.technique_id, plan)
    return [seen[key] for key in sorted(seen)]


class Coordinator(AgentBase):
    """Dispatches specialist agents and merges findings + emulation plans."""

    def __init__(
        self,
        backend,
        prompts_dir=None,
        mode: str = "auto",
        lab_scope: bool = False,
        research: bool = False,
        offline: bool = False,
    ) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"invalid mode {mode!r}; expected one of {VALID_MODES}")
        super().__init__("coordinator", backend, prompts_dir or default_prompts_dir())
        self.mode = mode
        self.lab_scope = lab_scope
        self.research = research
        self.offline = offline
        self.code_agent = CodeResearchAgent(backend, self.prompt_path.parent)
        self.threat_agent = ThreatResearchAgent(backend, self.prompt_path.parent)
        self.red_team_agent = RedTeamAgent(backend, self.prompt_path.parent)

    @property
    def redteam_active(self) -> bool:
        return self.mode == "redteam" or (self.mode == "auto" and self.lab_scope)

    def _dispatch_agents(self) -> list[AgentBase]:
        agents: list[AgentBase] = [self.code_agent, self.threat_agent]
        if self.redteam_active:
            agents.append(self.red_team_agent)
        return agents

    def analyze(self, target: Path | None, brief: str = "") -> CoordinatorResult:
        if target is not None:
            target = Path(target)
            category = classify(target)
            label = str(target)
            content = target.read_text(encoding="utf-8")
        else:
            category = "brief"
            label = "inline-brief"
            content = brief
        redteam = self.redteam_active
        prompt = (
            f"File: {label}\n"
            f"Category: {category}\n"
            f"Mode: {'redteam' if redteam else 'defensive'}\n"
            f"Lab-Scope: {'asserted (--lab)' if self.lab_scope else 'not asserted'}\n\n"
            f"Perform a security analysis of the following {'brief' if target is None else 'file content'}.\n\n"
            f"```\n{content}\n```"
        )
        findings: list[Finding] = []
        plans: list[EmulationPlan] = []
        refusals: list[Refusal] = []
        errors: list[str] = []
        agents_run: list[str] = []
        prompt_hashes: dict[str, str] = {self.name: self.prompt_hash}
        for agent in self._dispatch_agents():
            agents_run.append(agent.name)
            prompt_hashes[agent.name] = agent.prompt_hash
            try:
                output: AgentOutput = agent.run(prompt)
            except (ValueError, ValidationError, json.JSONDecodeError) as exc:
                # Real models sometimes produce unparseable output even after
                # the repair retry; record it and keep going.
                errors.append(f"{agent.name}: {exc}")
                continue
            if isinstance(output, Refusal):
                refusals.append(output)
            elif isinstance(output, AnalysisPayload):
                findings.extend(output.findings)
                plans.extend(output.emulation_plans)
            else:
                findings.extend(output)
        merged = dedupe_findings(findings)
        merged.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.confidence))
        merged_plans = dedupe_plans(plans)
        if self.research:
            # Research agent runs after merge/dedupe and attaches public
            # references (NVD CVEs, ATT&CK technique metadata) in place.
            from .research import ResearchAgent

            research_agent = ResearchAgent(
                self.backend, self.prompt_path.parent, offline=self.offline
            )
            agents_run.append(research_agent.name)
            prompt_hashes[research_agent.name] = research_agent.prompt_hash
            notes = research_agent.enrich(merged, merged_plans)
            errors.extend(f"{research_agent.name}: {note}" for note in notes)
        return CoordinatorResult(
            target=label,
            category=category,
            mode=self.mode,
            lab_scope=self.lab_scope,
            findings=merged,
            emulation_plans=merged_plans,
            refusals=refusals,
            errors=errors,
            prompt_hashes=prompt_hashes,
            agents_run=agents_run,
        )
