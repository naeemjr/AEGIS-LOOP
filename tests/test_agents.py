"""Agent tests: coordinator dispatch, dedupe of overlapping findings."""

from __future__ import annotations

from aegis_loop.agents.coordinator import Coordinator, dedupe_findings
from aegis_loop.backend import MockBackend
from aegis_loop.schemas import Finding
from conftest import valid_finding


def test_coordinator_dispatches_both_agents_and_dedupes(tmp_path, prompts_dir) -> None:
    target = tmp_path / "demo.c"
    target.write_text('int main(int argc, char **argv) { char b[8]; strcpy(b, argv[1]); }\n')

    backend = MockBackend()
    coordinator = Coordinator(backend, prompts_dir=prompts_dir)
    result = coordinator.analyze(target)

    # Both specialist agents ran (one backend call each, no repair retries).
    assert result.agents_run == ["code_research", "threat_research"]
    assert backend.calls == 2
    # MockBackend returns the same canned finding for both agents -> deduped to 1.
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "critical"
    assert finding.file == str(target)
    # Prompt hashes recorded for the manifest.
    assert set(result.prompt_hashes) == {"coordinator", "code_research", "threat_research"}


def test_dedupe_overlapping_findings() -> None:
    a = Finding(**valid_finding(title="Stack buffer overflow", lines="12-18", confidence=0.9))
    b = Finding(**valid_finding(title="stack  Buffer   Overflow", lines="15-20", confidence=0.7))
    c = Finding(**valid_finding(title="Stack buffer overflow", lines="40-42", confidence=0.8))
    d = Finding(**valid_finding(title="Format string issue", lines="12-18", confidence=0.6))

    merged = dedupe_findings([a, b, c, d])
    # b duplicates a (same title normalized, overlapping lines) -> dropped.
    # c has disjoint lines, d has a different title -> kept.
    assert len(merged) == 3
    # Higher-confidence duplicate (a, 0.9) is the one kept.
    titles = {f.title for f in merged}
    assert "Stack buffer overflow" in titles
    assert all(f.confidence != 0.7 for f in merged)


def test_findings_ordered_by_severity(tmp_path, prompts_dir) -> None:
    target = tmp_path / "demo.yaml"
    target.write_text("debug: true\n")

    backend = MockBackend()
    coordinator = Coordinator(backend, prompts_dir=prompts_dir)
    result = coordinator.analyze(target)
    assert len(result.findings) == 1  # both agents return the same canned config finding
    assert result.findings[0].severity == "high"
