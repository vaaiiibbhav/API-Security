"""Configuration model for SAGA."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    """Configuration for target API analysis."""

    base_url: str = Field(default="http://localhost:8000", description="Base URL of target API")
    spec_path: Path | None = Field(default=None, description="Path to OpenAPI/Swagger spec")


class LoggingConfig(BaseModel):
    """Configuration for logging."""

    level: str = Field(default="INFO", description="Log level (DEBUG, INFO, WARNING, ERROR)")
    format: str = Field(
        default="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        description="Log format string",
    )


class SagaConfig(BaseModel):
    """Global SAGA application configuration."""

    project_name: str = Field(default="SAGA Audit", description="Name of the audit project")
    target: TargetConfig = Field(default_factory=TargetConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    output_dir: Path = Field(default=Path("./output"), description="Directory for output reports")

    @classmethod
    def from_yaml(cls, yaml_path: Path | str) -> "SagaConfig":
        """Load configuration from a YAML file.

        Args:
            yaml_path: Path to the YAML configuration file.

        Returns:
            Instantiated SagaConfig instance.
        """
        path = Path(yaml_path)
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}

        return cls.model_validate(data)
