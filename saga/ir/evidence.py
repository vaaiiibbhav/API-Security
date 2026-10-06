"""Evidence model for tracing extracted facts back to source code."""

from pathlib import Path

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """Source code evidence supporting a semantic security fact."""

    source_file: Path | str | None = None
    source_line: int | None = None
    expression: str | None = None
    extraction_method: str = "ast_visitor"
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
