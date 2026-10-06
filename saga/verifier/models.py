"""Data models for SAGA static verification and vulnerability candidate classification."""

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    """Tri-state verification status for SAGA security analysis."""

    PROVEN = "PROVEN"
    UNPROVEN = "UNPROVEN"
    UNKNOWN = "UNKNOWN"


class CandidateVulnerability(str, Enum):
    """Candidate vulnerability classification prior to dynamic proving."""

    BOLA = "BOLA"
    BFLA = "BFLA"
    NONE = "NONE"


class EndpointAnalysisReport(BaseModel):
    """Detailed static verification report for a single endpoint."""

    http_method: str
    path: str
    handler_name: str
    source_file: Path | str | None = None
    source_line: int | None = None

    principal: str | None = None
    object_entity: str | None = None
    reference_param: str | None = None
    authorization_rule: str = "NONE"

    graph_nodes: list[str] = Field(default_factory=list)
    graph_edges: list[str] = Field(default_factory=list)

    result: VerificationStatus
    candidate: CandidateVulnerability = CandidateVulnerability.NONE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str = ""


class SAGAAnalysisSummary(BaseModel):
    """Complete project analysis report."""

    target_path: str
    discovered_endpoints: int
    reports: list[EndpointAnalysisReport] = Field(default_factory=list)
