#!/usr/bin/env python3
"""
Sensitive Files Scanner Plugin - Detecta arquivos sensíveis expostos
"""

import requests
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class SensitiveFilesPlugin(PluginInterface):
    """Plugin para detectar arquivos sensíveis expostos."""

    name = "sensitive_files"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Detects exposed sensitive files (.git, .env, backups, configs)"
    category = "vuln_scan"
    requires = ["requests"]

    # Arquivos sensíveis para testar
    SENSITIVE_FILES = [
        # Version control
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".gitignore",
        ".svn/entries",
        ".svn/wc.db",
        ".hg/store/00manifest.i",

        # Environment & Config
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "config.php",
        "config.json",
        "config.yml",
        "config.yaml",
        "configuration.php",
        "settings.php",
        "settings.json",
        "application.properties",
        "database.yml",
        "wp-config.php",
        "web.config",

        # Credentials
        "credentials.json",
        "secrets.json",
        "secret.key",
        "private.key",
        "id_rsa",
        "id_dsa",
        ".aws/credentials",
        ".ssh/id_rsa",
        ".ssh/config",

        # Backups
        "backup.sql",
        "backup.zip",
        "backup.tar.gz",
        "backup.bak",
        "db.sql",
        "database.sql",
        "dump.sql",
        "site.zip",
        "www.zip",
        "backup_2023.sql",
        "backup_2024.sql",

        # Logs
        "error.log",
        "access.log",
        "debug.log",
        "application.log",
        "laravel.log",
        "error_log",

        # Documentation
        "README.md",
        "INSTALL.md",
        "TODO.md",
        "CHANGELOG.md",
        "API.md",

        # Security
        "phpinfo.php",
        "info.php",
        "test.php",
        "debug.php",
        "adminer.php",
        "phpmyadmin/",

        # Deployment
        "docker-compose.yml",
        "Dockerfile",
        ".dockerignore",
        "Jenkinsfile",
        ".gitlab-ci.yml",
        ".travis.yml",
        "deploy.sh",

        # IDE
        ".idea/workspace.xml",
        ".vscode/settings.json",
        ".DS_Store",

        # Package managers
        "composer.json",
        "composer.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "Gemfile",
        "Gemfile.lock",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
    ]

    # Indicadores de exposição (keywords no response)
    EXPOSURE_INDICATORS = {
        '.git/': [b'ref:', b'refs/heads/', b'[core]'],
        '.env': [b'DB_PASSWORD', b'API_KEY', b'SECRET', b'AWS_ACCESS'],
        'config': [b'password', b'secret', b'api_key', b'database'],
        'backup': [b'CREATE TABLE', b'INSERT INTO', b'DROP TABLE'],
        '.ssh/': [b'-----BEGIN', b'PRIVATE KEY', b'ssh-rsa'],
        'composer.json': [b'"require"', b'"autoload"'],
        'package.json': [b'"dependencies"', b'"scripts"'],
    }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia site para arquivos sensíveis.

        Args:
            target: URL base (ex: https://example.com)
            **kwargs:
                timeout: Timeout em segundos (default: 5)
                user_agent: User-Agent customizado (opcional)

        Returns:
            Dicionário com arquivos expostos
        """
        timeout = kwargs.get('timeout', 5)
        user_agent = kwargs.get('user_agent', 'Mozilla/5.0')

        print(f"[*] Scanning {target} for exposed sensitive files...")

        exposed_files = []

        # Parse URL base
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            'User-Agent': user_agent
        }

        # Testa cada arquivo
        for i, filepath in enumerate(self.SENSITIVE_FILES, 1):
            if i % 10 == 0:
                print(f"[*] Progress: {i}/{len(self.SENSITIVE_FILES)}")

            # Constrói URL completa
            test_url = urljoin(base_url + '/', filepath)

            try:
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

                # Verifica se arquivo está acessível
                if response.status_code == 200:
                    # Verifica indicadores de conteúdo válido
                    is_exposed, indicator = self._check_exposure(filepath, response.content)

                    if is_exposed:
                        finding = {
                            'type': 'exposed_sensitive_file',
                            'severity': self._assess_severity(filepath),
                            'url': test_url,
                            'file': filepath,
                            'description': f'Exposed sensitive file: {filepath}',
                            'impact': self._get_impact(filepath),
                            'remediation': 'Remove or restrict access to sensitive files',
                            'evidence': {
                                'status_code': response.status_code,
                                'content_length': len(response.content),
                                'indicator': indicator,
                                'content_type': response.headers.get('Content-Type', '')
                            }
                        }

                        exposed_files.append(finding)

                        print(f"[!] EXPOSED! {filepath} - {test_url}")

            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except:
                pass

        print(f"\n[+] Found {len(exposed_files)} exposed sensitive files")

        self.results = exposed_files

        return {
            'exposed_files': exposed_files,
            'count': len(exposed_files),
            'target': target
        }

    def _check_exposure(self, filepath: str, content: bytes) -> tuple:
        """Verifica se arquivo realmente está exposto (não é 404 page)."""

        # Se resposta muito pequena, provavelmente é erro
        if len(content) < 10:
            return False, ""

        # Verifica indicadores específicos por tipo de arquivo
        for pattern, indicators in self.EXPOSURE_INDICATORS.items():
            if pattern in filepath.lower():
                for indicator in indicators:
                    if indicator in content:
                        return True, f"contains: {indicator.decode('utf-8', errors='ignore')}"

        # Se não tem indicador específico mas tem conteúdo, considera exposto
        # (para arquivos como README.md, CHANGELOG, etc.)
        if len(content) > 100:
            return True, f"content_length: {len(content)} bytes"

        return False, ""

    def _assess_severity(self, filepath: str) -> str:
        """Avalia severidade baseado no tipo de arquivo."""

        critical_patterns = [
            '.env', 'secret', 'credential', 'private', 'id_rsa',
            'backup.sql', 'database.sql', 'dump.sql'
        ]

        high_patterns = [
            '.git/', 'config', 'wp-config', 'web.config',
            'backup', '.ssh/', 'composer.lock'
        ]

        for pattern in critical_patterns:
            if pattern in filepath.lower():
                return 'critical'

        for pattern in high_patterns:
            if pattern in filepath.lower():
                return 'high'

        return 'medium'

    def _get_impact(self, filepath: str) -> str:
        """Retorna descrição do impacto."""

        if '.git/' in filepath:
            return 'Exposed Git repository - attacker can download entire source code'
        elif '.env' in filepath:
            return 'Environment file exposed - may contain passwords, API keys, secrets'
        elif 'backup' in filepath.lower() or '.sql' in filepath:
            return 'Database backup exposed - may contain sensitive user data'
        elif 'config' in filepath.lower():
            return 'Configuration file exposed - may contain credentials and system info'
        elif 'private' in filepath.lower() or 'id_rsa' in filepath:
            return 'Private key exposed - attacker can impersonate services/users'
        elif '.ssh/' in filepath:
            return 'SSH configuration exposed - may reveal internal infrastructure'
        else:
            return 'Sensitive file exposed - may aid in further attacks'
