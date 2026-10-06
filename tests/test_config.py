"""Tests for SAGA configuration model and YAML parsing."""

from pathlib import Path

import pytest

from saga.core.config import SagaConfig


def test_default_config():
    """Test default configuration values."""
    config = SagaConfig()
    assert config.project_name == "SAGA Audit"
    assert config.target.base_url == "http://localhost:8000"
    assert config.logging.level == "INFO"
    assert config.output_dir == Path("./output")


def test_yaml_config_loading(tmp_path: Path):
    """Test loading configuration from YAML file."""
    yaml_content = """
project_name: Custom SAGA Project
target:
  base_url: https://api.example.com
  spec_path: /tmp/openapi.json
logging:
  level: DEBUG
output_dir: /tmp/saga_reports
"""
    config_file = tmp_path / "saga_config.yaml"
    config_file.write_text(yaml_content, encoding="utf-8")

    config = SagaConfig.from_yaml(config_file)
    assert config.project_name == "Custom SAGA Project"
    assert config.target.base_url == "https://api.example.com"
    assert config.target.spec_path == Path("/tmp/openapi.json")
    assert config.logging.level == "DEBUG"
    assert config.output_dir == Path("/tmp/saga_reports")


def test_missing_yaml_file():
    """Test error raised when YAML file does not exist."""
    with pytest.raises(FileNotFoundError):
        SagaConfig.from_yaml("non_existent_config.yaml")
