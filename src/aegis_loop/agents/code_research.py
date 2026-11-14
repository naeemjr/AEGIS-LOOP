"""Code research agent: defensive static security review of supplied files."""

from __future__ import annotations

from .base import AgentBase


class CodeResearchAgent(AgentBase):
    def __init__(self, backend, prompts_dir=None) -> None:
        super().__init__("code_research", backend, prompts_dir)
