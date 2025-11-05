#!/usr/bin/env python3
"""
Logging utility
"""

import logging
import sys
from datetime import datetime
from pathlib import Path


# Global logger instance
_logger = None


def setup_logger(log_level='INFO', log_file=None):
    """Setup and configure logger"""
    global _logger

    if _logger is not None:
        return _logger

    # Create logger
    _logger = logging.getLogger('CloudPentest')
    _logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers
    _logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    _logger.addHandler(console_handler)

    # File handler (if log_file specified)
    if log_file:
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)

    return _logger


def get_logger():
    """Get logger instance"""
    global _logger

    if _logger is None:
        _logger = setup_logger()

    return _logger
