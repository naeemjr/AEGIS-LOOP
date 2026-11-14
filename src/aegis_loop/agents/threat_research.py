"""Threat research agent: STRIDE-lite defensive threat modeling.

Focuses on assets, trust boundaries, attacker preconditions, impact, and
mitigations.
"""

from __future__ import annotations

from .base import AgentBase


class ThreatResearchAgent(AgentBase):
    def __init__(self, backend, prompts_dir=None) -> None:
        super().__init__("threat_research", backend, prompts_dir)
