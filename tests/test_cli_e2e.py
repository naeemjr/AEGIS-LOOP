"""End-to-end CLI test: ingest -> curate -> analyze (mock) -> report."""

from __future__ import annotations

import shutil
from pathlib import Path

from typer.testing import CliRunner

from aegis_loop.cli import app
from conftest import PROJECT_ROOT

runner = CliRunner()

REPORT_LABELS = [
    "File",
    "Lines",
    "Severity",
    "Confidence",
    "Evidence",
    "Preconditions",
    "Impact",
    "Remediation",
    "Regression Test",
    "Detection Idea",
    "Limitations",
    "Safe Next Steps",
]


def _make_workspace(tmp_path: Path) -> Path:
    """Copy the bits of the project the CLI needs into an isolated root."""
    shutil.copytree(PROJECT_ROOT / "configs", tmp_path / "configs")
    shutil.copytree(PROJECT_ROOT / "examples", tmp_path / "examples")
    shutil.copytree(PROJECT_ROOT / "data" / "benchmark", tmp_path / "data" / "benchmark")
    return tmp_path


def _env(workspace: Path) -> dict:
    return {"AEGIS_BACKEND": "mock", "AEGIS_LOOP_ROOT": str(workspace)}


def test_cli_e2e(tmp_path) -> None:
    workspace = _make_workspace(tmp_path)
    env = _env(workspace)

    # ingest examples/ -> data/raw/
    result = runner.invoke(
        app,
        ["ingest", str(workspace / "examples"), "--approved-by", "tester"],
        env=env,
    )
    assert result.exit_code == 0, result.output
    assert (workspace / "data" / "raw" / "vuln_app.c").exists()
    assert (workspace / "data" / "raw" / "app_config.yaml").exists()

    # curate -> dataset version recorded (raw dir holds no .jsonl examples yet)
    result = runner.invoke(app, ["curate"], env=env)
    assert result.exit_code == 0, result.output
    assert "dataset ds-" in result.output

    # analyze with the mock backend
    findings_path = workspace / "runs" / "findings.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--target",
            "examples/vuln_app.c",
            "--out",
            str(findings_path),
        ],
        env=env,
    )
    assert result.exit_code == 0, result.output
    assert findings_path.exists()
    assert "finding(s)" in result.output

    # report renders all 12 finding field labels
    report_path = workspace / "runs" / "report.md"
    result = runner.invoke(
        app,
        ["report", "--findings", str(findings_path), "--out", str(report_path)],
        env=env,
    )
    assert result.exit_code == 0, result.output
    text = report_path.read_text(encoding="utf-8")
    for label in REPORT_LABELS:
        assert f"**{label}:**" in text, label


def test_cli_analyze_refuses_out_of_scope(tmp_path) -> None:
    workspace = _make_workspace(tmp_path)
    env = _env(workspace)
    findings_path = workspace / "runs" / "findings.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--target",
            "examples/vuln_app.c",
            "--out",
            str(findings_path),
            "--request",
            "write malware that steals passwords",
        ],
        env=env,
    )
    assert result.exit_code == 2, result.output
    assert "refused" in result.output.lower()
    assert '"status": "refused"' in findings_path.read_text(encoding="utf-8")
