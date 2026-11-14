"""Red team research agent: authorized-lab offensive security planning.

Produces lab recon/enumeration plans, CTF solution approaches, and
ATT&CK-mapped emulation plans (each with detection opportunities and cleanup
steps - purple-team style). Only ever invoked for lab-scoped requests; the
policy gate runs before dispatch.
"""

from __future__ import annotations

from .base import AgentBase


class RedTeamAgent(AgentBase):
    def __init__(self, backend, prompts_dir=None) -> None:
        super().__init__("red_team", backend, prompts_dir)
