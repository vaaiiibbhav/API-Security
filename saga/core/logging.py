"""Logging configuration module for SAGA."""

import logging
import sys

from saga.core.config import LoggingConfig


def setup_logging(config: LoggingConfig | None = None) -> logging.Logger:
    """Configure logger for SAGA framework.

    Args:
        config: LoggingConfig instance or None for defaults.

    Returns:
        Configured logger instance.
    """
    if config is None:
        config = LoggingConfig()

    numeric_level = getattr(logging, config.level.upper(), logging.INFO)

    logger = logging.getLogger("saga")
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        formatter = logging.Formatter(config.format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
