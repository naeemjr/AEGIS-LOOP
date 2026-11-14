"""Analyze flow: policy gate -> Coordinator -> findings/plans JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import load_yaml, project_root
from .agents.coordinator import VALID_MODES, Coordinator
from .backend import get_backend
from .policy import check_scope
from .schemas import utc_now


def research_enabled(flag: bool = False) -> bool:
    """Research enrichment is on via the --research flag or `research: true`
    in configs/base_model.yaml (the single documented config location)."""
    if flag:
        return True
    config = load_yaml(project_root() / "configs" / "base_model.yaml")
    return bool(config.get("research", False))


def resolve_target(target: Path) -> Path:
    target = Path(target)
    if target.is_absolute() and target.exists():
        return target
    candidate = project_root() / target
    if candidate.exists():
        return candidate
    if target.exists():
        return target
    raise FileNotFoundError(f"analysis target not found: {target}")


def analyze(
    target: Path | None = None,
    out: Path | None = None,
    request: str = "defensive security review of the supplied file",
    mode: str = "auto",
    lab: bool = False,
    backend=None,
    research: bool = False,
    offline: bool = False,
) -> dict[str, Any]:
    """Analyze a target file or inline brief and write the payload to ``out``.

    The scope policy is applied BEFORE any backend call (``lab_flag=lab``);
    refused requests produce a structured refusal payload without touching a
    model. ``mode`` selects auto/defensive/redteam dispatch; ``lab`` asserts
    authorized lab scope and is recorded in the output manifest. ``research``
    (or ``research: true`` in configs/base_model.yaml) runs the research agent
    after merge/dedupe to attach live public references; ``offline`` (or
    ``AEGIS_OFFLINE=1``) disables all research-agent network access.
    """
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode {mode!r}; expected one of {VALID_MODES}")
    if out is None:
        raise ValueError("an output path is required")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    scope_text = request if target is None else f"{request}\n{target}"
    scope = check_scope(scope_text, lab_flag=lab)

    if not scope.allowed:
        payload: dict[str, Any] = {
            "status": "refused",
            "target": str(target) if target else "inline-brief",
            "mode": mode,
            "lab": lab,
            "refusal": {
                "refusal": True,
                "reason": scope.refusal_message,
                "matched_patterns": scope.matched_patterns,
                "safe_alternative": (
                    "Rephrase as a defensive task, or - for authorized lab/CTF/"
                    "emulation work only - re-run with --lab or add a lab scope "
                    "marker (lab, CTF, private IP range, named training target, "
                    "ATT&CK technique ID)."
                ),
            },
            "findings": [],
            "emulation_plans": [],
            "created_at": utc_now(),
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    lab_scope = scope.lab_scope or lab
    research = research_enabled(research)
    backend = backend or get_backend()
    coordinator = Coordinator(
        backend, mode=mode, lab_scope=lab_scope, research=research, offline=offline
    )
    result = coordinator.analyze(
        resolve_target(target) if target is not None else None, brief=request
    )

    payload = {
        "status": "ok",
        "target": result.target,
        "category": result.category,
        "mode": mode,
        "lab": lab,
        "lab_scope": lab_scope,
        "matched_markers": scope.matched_markers,
        "research": research,
        "findings": [f.model_dump() for f in result.findings],
        "emulation_plans": [p.model_dump() for p in result.emulation_plans],
        "refusals": [r.model_dump() for r in result.refusals],
        "errors": result.errors,
        "prompt_hashes": result.prompt_hashes,
        "agents_run": result.agents_run,
        "backend": getattr(backend, "name", type(backend).__name__),
        "created_at": utc_now(),
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
