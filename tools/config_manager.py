#!/usr/bin/env python3
"""
Configuration Manager
Gerencia configurações do sistema de pentest
"""

import yaml
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging


class ConfigManager:
    """Gerencia configurações do sistema."""

    DEFAULT_CONFIG = {
        'general': {
            'output_dir': './output',
            'database': 'recon_discoveries.db',
            'log_level': 'INFO',
            'max_threads': 50,
            'timeout': 300
        },
        'plugins': {
            'enabled_categories': ['recon', 'vuln_scan'],
            'disabled_plugins': [],
            'python_plugins_dir': './plugins',
            'js_plugins_dir': './js_plugins'
        },
        'scanning': {
            'max_depth': 3,
            'follow_redirects': True,
            'verify_ssl': False,
            'user_agent': 'Mozilla/5.0 (Pentest Suite)',
            'rate_limit': 10,  # requests per second
            'blacklist_file': 'blacklist.json'
        },
        'reporting': {
            'format': 'json',
            'include_screenshots': False,
            'severity_filter': [],  # Empty = all
            'auto_export': True,
            'export_formats': ['json', 'html', 'markdown']
        },
        'osint': {
            'enable_whois': True,
            'enable_dns': True,
            'enable_ct_logs': True,
            'enable_social_media': False,
            'enable_breach_check': False,
            'hibp_api_key': '',
            'google_api_key': '',
            'shodan_api_key': ''
        },
        'notifications': {
            'enabled': False,
            'webhook_url': '',
            'notify_on_critical': True,
            'notify_on_complete': True
        },
        'advanced': {
            'concurrent_scans': 3,
            'retry_failed': True,
            'retry_count': 3,
            'save_raw_responses': False,
            'debug_mode': False
        }
    }

    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = config_file
        self.config = {}
        self.logger = logging.getLogger(__name__)
        self.load()

    def load(self) -> Dict:
        """Carrega configurações do arquivo."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
                    self.logger.info(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
                self.config = {}
        else:
            self.logger.info("Config file not found, using defaults")
            self.config = {}

        # Merge com defaults
        self.config = self._merge_config(self.DEFAULT_CONFIG, self.config)
        return self.config

    def _merge_config(self, default: Dict, user: Dict) -> Dict:
        """Merge de configurações do usuário com defaults."""
        result = default.copy()

        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value

        return result

    def save(self, config: Optional[Dict] = None):
        """Salva configurações no arquivo."""
        if config:
            self.config = config

        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Obtém valor de configuração por path.

        Args:
            key_path: Path da chave (ex: 'general.timeout')
            default: Valor padrão se chave não existir

        Returns:
            Valor da configuração
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any):
        """
        Define valor de configuração por path.

        Args:
            key_path: Path da chave (ex: 'general.timeout')
            value: Novo valor
        """
        keys = key_path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    def create_default_config(self, output_file: Optional[str] = None):
        """Cria arquivo de configuração padrão."""
        output_file = output_file or self.config_file

        with open(output_file, 'w') as f:
            yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)

        print(f"Default configuration created: {output_file}")
        print("\nEdit this file to customize your settings:")
        print(f"  vim {output_file}")
        print(f"  nano {output_file}")

    def validate(self) -> bool:
        """Valida configurações."""
        errors = []

        # Valida threads
        max_threads = self.get('general.max_threads')
        if not isinstance(max_threads, int) or max_threads < 1:
            errors.append("general.max_threads must be a positive integer")

        # Valida timeout
        timeout = self.get('general.timeout')
        if not isinstance(timeout, (int, float)) or timeout < 0:
            errors.append("general.timeout must be a non-negative number")

        # Valida rate_limit
        rate_limit = self.get('scanning.rate_limit')
        if not isinstance(rate_limit, (int, float)) or rate_limit < 0:
            errors.append("scanning.rate_limit must be a non-negative number")

        if errors:
            self.logger.error("Configuration validation failed:")
            for error in errors:
                self.logger.error(f"  - {error}")
            return False

        return True

    def print_config(self):
        """Imprime configuração atual."""
        print("=" * 60)
        print("CURRENT CONFIGURATION")
        print("=" * 60)
        print(yaml.dump(self.config, default_flow_style=False, sort_keys=False))
        print("=" * 60)

    def export_json(self, output_file: str):
        """Exporta configuração para JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"Configuration exported to: {output_file}")


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Configuration Manager')
    parser.add_argument('--create', action='store_true',
                       help='Create default config file')
    parser.add_argument('--print', action='store_true',
                       help='Print current configuration')
    parser.add_argument('--validate', action='store_true',
                       help='Validate configuration')
    parser.add_argument('--export', metavar='FILE',
                       help='Export configuration to JSON')
    parser.add_argument('--config', default='config.yaml',
                       help='Config file path (default: config.yaml)')

    args = parser.parse_args()

    config_manager = ConfigManager(args.config)

    if args.create:
        config_manager.create_default_config()
    elif args.print:
        config_manager.print_config()
    elif args.validate:
        if config_manager.validate():
            print("✓ Configuration is valid")
        else:
            print("✗ Configuration has errors")
            sys.exit(1)
    elif args.export:
        config_manager.export_json(args.export)
    else:
        parser.print_help()
