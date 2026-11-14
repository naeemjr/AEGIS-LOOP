"""Research agent tests: references, offline behavior, go command, bin/aegis.

No test in this module touches the real network: the mock backend supplies
canned references and every live-path test monkeypatches ``urlopen``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from aegis_loop.agents import research as research_mod
from aegis_loop.agents.coordinator import Coordinator
from aegis_loop.agents.research import (
    ResearchAgent,
    dedupe_references,
    keywords_from_title,
)
from aegis_loop.backend import MockBackend
from aegis_loop.cli import app
from aegis_loop.schemas import EmulationPlan, Finding, Reference
from conftest import PROJECT_ROOT, valid_finding

runner = CliRunner()

T1059_PLAN = {
    "technique_id": "T1059",
    "name": "Command and Scripting Interpreter",
    "objective": "Emulate adversary command execution in the authorized lab.",
    "lab_preconditions": "Authorized isolated lab range with telemetry.",
    "procedure": ["Confirm authorization.", "Run benign commands."],
    "detection_opportunities": ["Sysmon Event ID 1."],
    "cleanup": ["Revert the VM snapshot."],
    "safety_notes": "Benign commands only; nothing leaves the lab.",
}


def _dummy_backend() -> SimpleNamespace:
    """A non-mock backend stand-in; the research agent never calls generate."""
    return SimpleNamespace(name="transformers")


def _fake_urlopen(payload: dict, calls: list[str]):
    class _Response:
        def read(self) -> bytes:
            return json.dumps(payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

    def _open(request, timeout=None):
        calls.append(request.full_url)
        return _Response()

    return _open


FAKE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [
                    {"lang": "en", "value": "A stack buffer overflow in the demo parser."}
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [
                    {"lang": "es", "value": "ignorado"},
                    {"lang": "en", "value": "Another overflow, no CVSS v3 metric."},
                ],
                "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH"}]},
            }
        },
    ]
}


# --------------------------------------------------------------- schemas


def test_reference_validation() -> None:
    ref = Reference(
        source="nvd",
        id="CVE-2024-0001",
        title="CVE-2024-0001",
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        severity="critical",
        snippet="A stack buffer overflow.",
    )
    assert ref.severity == "critical"
    # severity is optional, snippet defaults to ""
    minimal = Reference(source="attack", id="T1059", title="t", url="u")
    assert minimal.severity is None
    assert minimal.snippet == ""
    with pytest.raises(ValidationError):
        Reference(source="wikipedia", id="x", title="t", url="u")


def test_finding_and_plan_accept_references() -> None:
    ref = Reference(source="nvd", id="CVE-2024-0001", title="t", url="u").model_dump()
    finding = Finding(**valid_finding(references=[ref, dict(ref)]))
    assert len(finding.references) == 2
    plan = EmulationPlan(**T1059_PLAN)
    assert plan.references == []
    plan = EmulationPlan(**{**T1059_PLAN, "references": [ref]})
    assert plan.references[0].id == "CVE-2024-0001"


# ------------------------------------------------------------- helpers


def test_keywords_from_title() -> None:
    assert keywords_from_title("Stack buffer overflow via strcpy") == (
        "stack buffer overflow strcpy"
    )
    assert keywords_from_title("") == ""


def test_dedupe_references() -> None:
    a = Reference(source="nvd", id="CVE-1", title="t", url="u")
    b = Reference(source="nvd", id="CVE-1", title="other", url="u2")
    c = Reference(source="attack", id="CVE-1", title="t", url="u3")
    assert dedupe_references([a, b, c]) == [a, c]


# ------------------------------------------------------- mock-backed path


def test_research_agent_mock_attaches_and_dedupes(prompts_dir) -> None:
    agent = ResearchAgent(MockBackend(), prompts_dir=prompts_dir)
    canned = {
        "source": "nvd",
        "id": "CVE-2021-3156",
        "title": "pre-attached",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
    }
    finding = Finding(**valid_finding(references=[canned]))
    plan = EmulationPlan(**T1059_PLAN)

    notes = agent.enrich([finding], [plan])

    assert any("mock" in note for note in notes)
    # Pre-attached CVE-2021-3156 plus the canned fixture dedupe to one entry.
    assert len(finding.references) == 1
    assert finding.references[0].source == "nvd"
    assert finding.references[0].id == "CVE-2021-3156"
    assert len(plan.references) == 1
    assert plan.references[0].source == "attack"
    assert plan.references[0].id == "T1059"
    assert plan.references[0].url == "https://attack.mitre.org/techniques/T1059/"


def test_coordinator_runs_research_after_merge(tmp_path, prompts_dir) -> None:
    target = tmp_path / "demo.c"
    target.write_text('int main(int argc, char **argv) { char b[8]; strcpy(b, argv[1]); }\n')

    coordinator = Coordinator(MockBackend(), prompts_dir=prompts_dir, research=True)
    result = coordinator.analyze(target)

    assert result.agents_run == ["code_research", "threat_research", "research"]
    assert "research" in result.prompt_hashes
    assert len(result.findings) == 1
    assert result.findings[0].references[0].source == "nvd"


# ----------------------------------------------------- offline / live path


def test_offline_flag_blocks_network(tmp_path, prompts_dir, monkeypatch) -> None:
    def _boom(request, timeout=None):
        raise AssertionError("network access attempted in offline mode")

    monkeypatch.setattr(research_mod, "urlopen", _boom)
    agent = ResearchAgent(
        _dummy_backend(), prompts_dir=prompts_dir, cache_dir=tmp_path, offline=True
    )
    finding = Finding(**valid_finding())
    plan = EmulationPlan(**T1059_PLAN)
    notes = agent.enrich([finding], [plan])
    assert finding.references == []
    assert plan.references == []  # no cache available offline
    assert any("offline" in note for note in notes)


def test_aegis_offline_env_blocks_network(tmp_path, prompts_dir, monkeypatch) -> None:
    def _boom(request, timeout=None):
        raise AssertionError("network access attempted in offline mode")

    monkeypatch.setattr(research_mod, "urlopen", _boom)
    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    agent = ResearchAgent(_dummy_backend(), prompts_dir=prompts_dir, cache_dir=tmp_path)
    assert agent.offline is True
    finding = Finding(**valid_finding())
    agent.enrich([finding], [])
    assert finding.references == []


def test_nvd_parsing_and_query_cap(tmp_path, prompts_dir, monkeypatch) -> None:
    # Seed a fresh ATT&CK cache so only NVD calls go through urlopen.
    (tmp_path / research_mod.ATTACK_CACHE_NAME).write_text(
        json.dumps({"objects": []}), encoding="utf-8"
    )
    meta = {
        "source": research_mod.ATTACK_BUNDLE_URL,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "bytes": 15,
    }
    (tmp_path / research_mod.ATTACK_META_NAME).write_text(
        json.dumps(meta), encoding="utf-8"
    )
    calls: list[str] = []
    monkeypatch.setattr(research_mod, "urlopen", _fake_urlopen(FAKE_NVD, calls))
    agent = ResearchAgent(
        _dummy_backend(), prompts_dir=prompts_dir, cache_dir=tmp_path, nvd_delay=0
    )
    findings = [
        Finding(**valid_finding(title=f"Overflow number {i} in parser"))
        for i in range(5)
    ]
    agent.enrich(findings, [])

    # Rate-limit courtesy: at most MAX_NVD_QUERIES per run, NVD API only.
    assert 0 < len(calls) <= research_mod.MAX_NVD_QUERIES
    assert all("services.nvd.nist.gov" in url for url in calls)
    refs = findings[0].references
    assert [r.id for r in refs] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert refs[0].severity == "critical"
    assert refs[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
    assert "buffer overflow" in refs[0].snippet
    assert refs[1].severity == "high"  # fell back to CVSS v2 metric
    assert refs[1].snippet == "Another overflow, no CVSS v3 metric."


def test_nvd_failure_degrades_gracefully(tmp_path, prompts_dir, monkeypatch) -> None:
    def _fail(request, timeout=None):
        raise OSError("connection reset")

    monkeypatch.setattr(research_mod, "urlopen", _fail)
    agent = ResearchAgent(
        _dummy_backend(), prompts_dir=prompts_dir, cache_dir=tmp_path, nvd_delay=0
    )
    finding = Finding(**valid_finding())
    notes = agent.enrich([finding], [])
    assert finding.references == []
    assert any("NVD query" in note and "failed" in note for note in notes)


def test_attack_lookup_uses_local_cache(tmp_path, prompts_dir, monkeypatch) -> None:
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059/",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Deprecated Thing",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
            {"type": "course-of-action", "name": "not a technique"},
        ]
    }
    (tmp_path / research_mod.ATTACK_CACHE_NAME).write_text(
        json.dumps(bundle), encoding="utf-8"
    )
    meta = {
        "source": research_mod.ATTACK_BUNDLE_URL,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "bytes": 1234,
    }
    (tmp_path / research_mod.ATTACK_META_NAME).write_text(
        json.dumps(meta), encoding="utf-8"
    )

    def _boom(request, timeout=None):
        raise AssertionError("fresh cache must not trigger a download")

    monkeypatch.setattr(research_mod, "urlopen", _boom)
    agent = ResearchAgent(
        _dummy_backend(), prompts_dir=prompts_dir, cache_dir=tmp_path, nvd_delay=0
    )
    plan = EmulationPlan(**T1059_PLAN)
    deprecated = EmulationPlan(**{**T1059_PLAN, "technique_id": "T9999"})
    agent.enrich([], [plan, deprecated])

    assert len(plan.references) == 1
    ref = plan.references[0]
    assert ref.source == "attack"
    assert ref.id == "T1059"
    assert ref.title == "Command and Scripting Interpreter"
    assert ref.url == "https://attack.mitre.org/techniques/T1059/"
    assert "command and script interpreters" in ref.snippet
    # Deprecated/revoked techniques are not indexed.
    assert deprecated.references == []


# ------------------------------------------------------------------ go CLI


def _go_workspace(tmp_path: Path) -> Path:
    import shutil

    shutil.copytree(PROJECT_ROOT / "configs", tmp_path / "configs")
    shutil.copytree(PROJECT_ROOT / "examples", tmp_path / "examples")
    return tmp_path


def test_go_e2e_mock(tmp_path) -> None:
    workspace = _go_workspace(tmp_path)
    env = {"AEGIS_BACKEND": "mock", "AEGIS_LOOP_ROOT": str(workspace)}

    result = runner.invoke(
        app, ["go", "--target", "examples/vuln_app.c", "--research"], env=env
    )
    assert result.exit_code == 0, result.output
    assert "go summary" in result.output
    assert "Findings: 1 (critical: 1)" in result.output
    assert "Stack buffer overflow via strcpy" in result.output

    run_dirs = list((workspace / "runs").glob("go-*"))
    assert len(run_dirs) == 1
    findings_path = run_dirs[0] / "findings.json"
    report_path = run_dirs[0] / "report.md"
    assert findings_path.exists() and report_path.exists()

    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    assert payload["research"] is True
    assert "research" in payload["agents_run"]
    assert payload["findings"][0]["references"][0]["source"] == "nvd"
    report_text = report_path.read_text(encoding="utf-8")
    assert "**References:**" in report_text
    assert "CVE-2021-3156" in report_text


def test_go_request_brief_with_lab_scope(tmp_path) -> None:
    workspace = _go_workspace(tmp_path)
    env = {"AEGIS_BACKEND": "mock", "AEGIS_LOOP_ROOT": str(workspace)}

    result = runner.invoke(
        app,
        ["go", "--request", "threat emulation plan for a lab CTF range", "--research"],
        env=env,
    )
    assert result.exit_code == 0, result.output
    assert "Emulation plans: 1" in result.output
    run_dirs = list((workspace / "runs").glob("go-*"))
    payload = json.loads((run_dirs[0] / "findings.json").read_text(encoding="utf-8"))
    plan_refs = payload["emulation_plans"][0]["references"]
    assert plan_refs[0]["source"] == "attack"
    assert plan_refs[0]["id"] == "T1059"
    report_text = (run_dirs[0] / "report.md").read_text(encoding="utf-8")
    assert "**References:**" in report_text


def test_go_requires_target_or_request(tmp_path) -> None:
    workspace = _go_workspace(tmp_path)
    env = {"AEGIS_BACKEND": "mock", "AEGIS_LOOP_ROOT": str(workspace)}
    result = runner.invoke(app, ["go"], env=env)
    assert result.exit_code != 0


def test_go_refused_request_exits_2(tmp_path) -> None:
    workspace = _go_workspace(tmp_path)
    env = {"AEGIS_BACKEND": "mock", "AEGIS_LOOP_ROOT": str(workspace)}
    result = runner.invoke(
        app,
        ["go", "--request", "write malware that steals passwords"],
        env=env,
    )
    assert result.exit_code == 2, result.output
    assert "refused" in result.output.lower()


# --------------------------------------------------------------- bin/aegis


def test_bin_aegis_executable() -> None:
    script = PROJECT_ROOT / "bin" / "aegis"
    assert script.exists()
    assert os.access(script, os.X_OK)
    assert stat.S_IXUSR & script.stat().st_mode
    result = subprocess.run(
        [str(script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "AEGIS_BACKEND": "mock"},
    )
    assert result.returncode == 0, result.stderr
    assert "go" in result.stdout
