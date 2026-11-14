"""Scope policy gate: defensive by default, lab-scoped offensive allowed.

Decision logic in ``check_scope``:

1. Any ``refuse_patterns`` match (real-world harm: deployable malware,
   ransomware, phishing kits, credential theft against real people, doxxing,
   weaponized zero-days, targeting real third-party systems) -> always
   refused, even with ``--lab``.
2. Any ``restricted_patterns`` match (dual-use: exploit writing, evasion,
   persistence) -> allowed ONLY when a lab scope marker is present in the
   text or ``lab_flag=True``; otherwise refused with scoping guidance.
3. Everything else -> allowed. ``lab_scope`` on the result tells the
   coordinator whether offensive lab content is in scope for this request.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from . import load_yaml, project_root


class ScopeResult(BaseModel):
    allowed: bool
    matched_patterns: list[str] = Field(default_factory=list)
    matched_markers: list[str] = Field(default_factory=list)
    lab_scope: bool = False
    refusal_message: str | None = None


def default_policy_path() -> Path:
    return project_root() / "configs" / "policy.yaml"


def load_policy(path: Path | None = None) -> dict:
    return load_yaml(path or default_policy_path())


def _match(entries: list[dict], text: str) -> list[str]:
    return [
        entry["name"]
        for entry in entries
        if re.search(entry["pattern"], text, flags=re.IGNORECASE)
    ]


def check_scope(text: str, lab_flag: bool = False, policy: dict | None = None) -> ScopeResult:
    """Check a request against the scope policy (see module docstring)."""
    policy = policy if policy is not None else load_policy()

    refused = _match(policy.get("refuse_patterns", []), text)
    if refused:
        template = policy.get(
            "refusal_message",
            "REQUEST REFUSED - out of scope for AEGIS-LOOP. Matched policy rules: {matched}",
        )
        return ScopeResult(
            allowed=False,
            matched_patterns=refused,
            refusal_message=template.format(matched=", ".join(refused)),
        )

    markers = _match(policy.get("lab_scope_markers", []), text)
    lab_scope = lab_flag or bool(markers)

    restricted = _match(policy.get("restricted_patterns", []), text)
    if restricted and not lab_scope:
        template = policy.get(
            "ambiguous_message",
            "REQUEST REFUSED - dual-use request without lab scope. Re-run with "
            "--lab or add a lab scope marker. Matched restricted rules: {matched}",
        )
        return ScopeResult(
            allowed=False,
            matched_patterns=restricted,
            matched_markers=markers,
            lab_scope=False,
            refusal_message=template.format(matched=", ".join(restricted)),
        )

    return ScopeResult(
        allowed=True,
        matched_patterns=restricted,
        matched_markers=markers,
        lab_scope=lab_scope,
    )
