"""Multi-agent defensive analysis: base agent, coordinator, specialists."""

from .base import AgentBase, AgentOutput, parse_structured_output
from .code_research import CodeResearchAgent
from .threat_research import ThreatResearchAgent
from .red_team import RedTeamAgent
from .data_curator import DataCuratorAgent
from .coordinator import Coordinator

__all__ = [
    "AgentBase",
    "AgentOutput",
    "parse_structured_output",
    "CodeResearchAgent",
    "ThreatResearchAgent",
    "RedTeamAgent",
    "DataCuratorAgent",
    "Coordinator",
]
