"""aegis-loop command line interface."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from . import analyze as analyze_mod
from . import curate as curate_mod
from . import ingest as ingest_mod
from . import report as report_mod
from . import train as train_mod
from . import project_root
from .backend import get_backend
from .curate import resolve_latest_dataset
from .evaluate import apply_evaluation, run_evaluation

app = typer.Typer(
    name="aegis-loop",
    help="Versioned LoRA/QLoRA fine-tuning and multi-agent analysis pipeline "
    "for DEFENSIVE security research.",
    no_args_is_help=True,
)


@app.command()
def ingest(
    sources: list[Path] = typer.Argument(..., help="Files or directories to ingest."),
    approved_by: str = typer.Option(..., help="Name of the human approver."),
) -> None:
    """Copy approved files into data/raw/ and record them in the registry."""
    records = ingest_mod.ingest(sources, approved_by=approved_by)
    for record in records:
        typer.echo(f"ingested {record.dest_path} (sha256={record.sha256[:12]}...)")
    typer.echo(f"{len(records)} file(s) ingested.")


@app.command()
def curate() -> None:
    """Curate raw approved records into a versioned TrainingExample dataset."""
    result = curate_mod.curate()
    typer.echo(
        f"dataset {result.version}: {result.emitted} emitted, "
        f"{result.skipped_not_approved} not approved, "
        f"{result.rejected_invalid} schema-invalid, "
        f"{result.rejected_out_of_scope} out-of-scope"
    )
    typer.echo(f"written to {result.dataset_path}")


@app.command()
def train(
    smoke: bool = typer.Option(False, help="Use the tiny smoke model instead of the 7B base."),
    max_steps: Optional[int] = typer.Option(
        None, help="Override training with a fixed number of optimizer steps."
    ),
    max_length: Optional[int] = typer.Option(
        None, help="Override max sequence length (e.g. 1024 to fit VRAM)."
    ),
) -> None:
    """Run QLoRA SFT on the latest curated dataset (requires ML extras)."""
    try:
        adapter_dir = train_mod.train(
            smoke=smoke, max_steps=max_steps, max_length_override=max_length
        )
    except ImportError as exc:
        typer.echo(f"Training unavailable: {exc}", err=True)
        raise typer.Exit(code=1)
    except FileNotFoundError as exc:
        typer.echo(f"Cannot train: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"adapter saved to {adapter_dir}")


@app.command()
def evaluate(
    adapter_version: Optional[int] = typer.Option(
        None, help="Adapter version v<N> to evaluate; omit to evaluate the base model."
    ),
) -> None:
    """Evaluate an adapter (or the base model) on the fixed benchmark."""
    if adapter_version is not None:
        from .backend import backend_for_adapter
        from .registry import get_adapter

        record = get_adapter(adapter_version)
        if record is None:
            typer.echo(f"adapter v{adapter_version} not found in registry", err=True)
            raise typer.Exit(code=1)
        try:
            backend = backend_for_adapter(record)
        except RuntimeError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1)
    else:
        backend = get_backend()
    version_label = str(adapter_version) if adapter_version is not None else "base"
    try:
        dataset_version, _ = resolve_latest_dataset()
    except FileNotFoundError:
        dataset_version = "unknown"
    result = run_evaluation(
        backend, adapter_version=version_label, dataset_version=dataset_version
    )
    typer.echo(f"composite={result.scores.composite:.3f} "
               f"schema={result.scores.schema_validity:.3f} "
               f"severity={result.scores.severity_calibration:.3f} "
               f"evidence={result.scores.evidence_quality:.3f} "
               f"remediation={result.scores.remediation_quality:.3f}")
    typer.echo(f"critical_policy_failures={result.critical_policy_failures}")
    promoted = apply_evaluation(result)
    typer.echo("promoted to incumbent" if promoted else "not promoted")


@app.command()
def analyze(
    target: Optional[Path] = typer.Option(
        None, help="File to analyze; omit to analyze the --request text as a brief."
    ),
    out: Path = typer.Option(..., help="Where to write the findings JSON."),
    request: str = typer.Option(
        "defensive security review of the supplied file",
        help="Natural-language description of the analysis request.",
    ),
    mode: str = typer.Option(
        "auto", help="Agent dispatch mode: auto | defensive | redteam."
    ),
    lab: bool = typer.Option(
        False,
        "--lab",
        help="Assert authorized lab scope (CTF/emulation range). Recorded in the manifest.",
    ),
    research: bool = typer.Option(
        False,
        "--research",
        help="Attach live public references (NVD CVEs, ATT&CK techniques) via the research agent.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Disable all research-agent network access (also AEGIS_OFFLINE=1).",
    ),
) -> None:
    """Run the multi-agent analysis on a target file or request brief."""
    if mode not in ("auto", "defensive", "redteam"):
        raise typer.BadParameter("mode must be one of: auto, defensive, redteam")
    payload = analyze_mod.analyze(
        target=target, out=out, request=request, mode=mode, lab=lab,
        research=research, offline=offline,
    )
    if payload["status"] == "refused":
        typer.echo("request refused by scope policy:")
        typer.echo(payload["refusal"]["reason"])
        raise typer.Exit(code=2)
    typer.echo(
        f"{len(payload['findings'])} finding(s), "
        f"{len(payload['emulation_plans'])} emulation plan(s) written to {out}"
    )


@app.command()
def report(
    findings: Path = typer.Option(..., help="Findings JSON produced by `analyze`."),
    out: Path = typer.Option(..., help="Where to write the Markdown report."),
) -> None:
    """Render a findings JSON payload into a Markdown report."""
    report_mod.write_report(findings, out)
    typer.echo(f"report written to {out}")


@app.command()
def go(
    target: Optional[Path] = typer.Option(
        None, help="File to analyze; omit to analyze the --request text as a brief."
    ),
    request: Optional[str] = typer.Option(
        None, help="Natural-language analysis request / brief."
    ),
    mode: str = typer.Option(
        "auto", help="Agent dispatch mode: auto | defensive | redteam."
    ),
    lab: bool = typer.Option(
        False,
        "--lab",
        help="Assert authorized lab scope (CTF/emulation range). Recorded in the manifest.",
    ),
    research: bool = typer.Option(
        False,
        "--research",
        help="Attach live public references (NVD CVEs, ATT&CK techniques) via the research agent.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Disable all research-agent network access (also AEGIS_OFFLINE=1).",
    ),
    out_dir: Optional[Path] = typer.Option(
        None, "--out-dir", help="Output directory (default: runs/go-<timestamp>/)."
    ),
) -> None:
    """One-command pipeline: policy gate -> analyze -> report -> terminal summary."""
    if target is None and not request:
        raise typer.BadParameter("provide --target <path> or --request <text>")
    if mode not in ("auto", "defensive", "redteam"):
        raise typer.BadParameter("mode must be one of: auto, defensive, redteam")

    if out_dir is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = project_root() / "runs" / f"go-{stamp}"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.json"
    report_path = out_dir / "report.md"

    payload = analyze_mod.analyze(
        target=target,
        out=findings_path,
        request=request or "defensive security review of the supplied file",
        mode=mode,
        lab=lab,
        research=research,
        offline=offline,
    )
    if payload["status"] == "refused":
        typer.echo("request refused by scope policy:")
        typer.echo(payload["refusal"]["reason"])
        raise typer.Exit(code=2)

    report_mod.write_report(findings_path, report_path)

    findings = payload["findings"]
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
    counts = ", ".join(
        f"{sev}: {severity_counts[sev]}"
        for sev in ("critical", "high", "medium", "low", "info")
        if sev in severity_counts
    )

    typer.echo("== AEGIS-LOOP go summary ==")
    typer.echo(f"Target: {payload['target']}")
    typer.echo(f"Backend: {payload.get('backend', 'unknown')}")
    typer.echo(f"Findings: {len(findings)}" + (f" ({counts})" if counts else ""))
    if findings:
        typer.echo("Top findings:")
        for index, finding in enumerate(findings[:5], start=1):
            typer.echo(f"  {index}. [{finding['severity']}] {finding['title']}")
    typer.echo(f"Emulation plans: {len(payload['emulation_plans'])}")
    typer.echo(f"Findings JSON: {findings_path}")
    typer.echo(f"Report: {report_path}")


if __name__ == "__main__":
    app()
