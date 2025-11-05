#!/usr/bin/env python3
"""
Configuration Settings
"""

import os
import yaml
from pathlib import Path


class Settings:
    """Application settings"""

    def __init__(self, config_file=None):
        self.config_file = config_file

        # Default settings
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.report_dir = os.getenv('REPORT_DIR', 'reports')
        self.max_threads = int(os.getenv('MAX_THREADS', '5'))
        self.timeout = int(os.getenv('TIMEOUT', '30'))

        # Tool settings
        self.enable_nmap = True
        self.enable_sqlmap = True
        self.enable_nikto = True
        self.enable_nuclei = True

        # Scanner settings
        self.max_scan_depth = 3
        self.max_files_to_scan = 1000
        self.follow_redirects = True
        self.verify_ssl = False

        # API key testing settings
        self.test_aws_keys = True
        self.test_azure_keys = True
        self.test_gcp_keys = True
        self.test_generic_keys = True

        # Load from config file if provided
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)

    def load_from_file(self, config_file):
        """Load settings from YAML config file"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)

            # Update settings from config
            if config:
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)

        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

    def to_dict(self):
        """Convert settings to dictionary"""
        return {
            key: value
            for key, value in self.__dict__.items()
            if not key.startswith('_')
        }
