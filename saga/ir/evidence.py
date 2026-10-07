"""Evidence model for tracing extracted facts back to source code."""

from pathlib import Path

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """Source code evidence supporting a semantic security fact."""

    source_file: Path | str | None = None
    source_line: int | None = None
    start_line: int | None = None
    end_line: int | None = None
    expression: str | None = None
    symbol: str | None = None
    node_type: str | None = None
    source_kind: str = "ast_visitor"  # e.g., "route", "dependency", "predicate", "sink"
    semantic_role: str = "general"     # e.g., "dominating_ownership_check"
    extraction_method: str = "ast_visitor"
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)

