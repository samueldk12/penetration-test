#!/usr/bin/env python3
"""
API Key Scanner
Scans files and directories for exposed API keys and credentials
"""

import os
import re
from pathlib import Path
from utils.logger import get_logger
from modules.aws_tester import AWSKeyTester
from modules.azure_tester import AzureKeyTester
from modules.gcp_tester import GCPKeyTester
from modules.generic_cloud_tester import GenericCloudTester


class APIKeyScanner:
    """Scan for exposed API keys in files and text"""

    # File extensions to scan
    SCANNABLE_EXTENSIONS = [
        '.txt', '.log', '.env', '.config', '.conf', '.ini',
        '.json', '.yaml', '.yml', '.xml',
        '.py', '.js', '.java', '.php', '.rb', '.go', '.rs',
        '.sh', '.bash', '.zsh',
        '.md', '.rst', '.html', '.htm',
        '.sql', '.backup', '.bak',
        '.pem', '.key', '.crt', '.cert',
        '.properties', '.cfg'
    ]

    # Directories to skip
    SKIP_DIRECTORIES = [
        '.git', '.svn', '.hg',
        'node_modules', 'vendor', 'venv', 'env',
        '__pycache__', '.cache',
        'dist', 'build', 'target',
        '.idea', '.vscode',
        'logs', 'tmp', 'temp'
    ]

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()

    def scan_directory(self, directory, max_files=1000):
        """Scan directory for exposed API keys"""
        self.logger.info(f"Scanning directory for API keys: {directory}")

        found_keys = []
        files_scanned = 0

        for root, dirs, files in os.walk(directory):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                if files_scanned >= max_files:
                    self.logger.warning(f"Reached max files limit: {max_files}")
                    break

                file_path = os.path.join(root, file)
                file_ext = Path(file).suffix.lower()

                # Only scan specific file types
                if file_ext not in self.SCANNABLE_EXTENSIONS:
                    continue

                # Skip large files (> 5MB)
                try:
                    if os.path.getsize(file_path) > 5 * 1024 * 1024:
                        continue
                except:
                    continue

                keys = self.scan_file(file_path)
                if keys:
                    for key in keys:
                        key['file'] = file_path
                    found_keys.extend(keys)

                files_scanned += 1

        self.logger.info(f"Scanned {files_scanned} files, found {len(found_keys)} potential keys")

        return found_keys

    def scan_file(self, file_path):
        """Scan a single file for API keys"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return self.scan_text(content)
        except Exception as e:
            self.logger.debug(f"Error scanning file {file_path}: {str(e)}")
            return []

    def scan_text(self, text):
        """Scan text for API keys"""
        found_keys = []

        # AWS keys
        aws_keys = AWSKeyTester.extract_keys_from_text(text)
        found_keys.extend(aws_keys)

        # Azure keys
        azure_keys = AzureKeyTester.extract_keys_from_text(text)
        found_keys.extend(azure_keys)

        # GCP keys
        gcp_keys = GCPKeyTester.extract_keys_from_text(text)
        found_keys.extend(gcp_keys)

        # Generic cloud service keys
        generic_keys = GenericCloudTester.extract_keys_from_text(text)
        found_keys.extend(generic_keys)

        # Additional patterns for common secrets
        additional_keys = self._scan_generic_secrets(text)
        found_keys.extend(additional_keys)

        return found_keys

    def _scan_generic_secrets(self, text):
        """Scan for generic secret patterns"""
        secrets = []

        patterns = {
            'password': [
                r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'pwd\s*[=:]\s*["\']([^"\']{8,})["\']',
                r'passwd\s*[=:]\s*["\']([^"\']{8,})["\']',
            ],
            'api_key': [
                r'api[_-]?key\s*[=:]\s*["\']([^"\']{16,})["\']',
                r'apikey\s*[=:]\s*["\']([^"\']{16,})["\']',
            ],
            'secret': [
                r'secret\s*[=:]\s*["\']([^"\']{16,})["\']',
                r'client[_-]?secret\s*[=:]\s*["\']([^"\']{16,})["\']',
            ],
            'token': [
                r'token\s*[=:]\s*["\']([^"\']{16,})["\']',
                r'auth[_-]?token\s*[=:]\s*["\']([^"\']{16,})["\']',
                r'access[_-]?token\s*[=:]\s*["\']([^"\']{16,})["\']',
            ],
            'private_key': [
                r'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----',
            ],
            'connection_string': [
                r'mongodb(\+srv)?://[^\s"\']+',
                r'mysql://[^\s"\']+',
                r'postgres(ql)?://[^\s"\']+',
                r'redis://[^\s"\']+',
            ],
            'database_password': [
                r'DB_PASSWORD\s*[=:]\s*["\']([^"\']+)["\']',
                r'DATABASE_PASSWORD\s*[=:]\s*["\']([^"\']+)["\']',
            ],
        }

        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        value = match[0] if match else ''
                    else:
                        value = match

                    # Skip common false positives
                    if self._is_false_positive(value):
                        continue

                    secrets.append({
                        'provider': 'generic',
                        'service': secret_type,
                        'key': value,
                        'type': secret_type
                    })

        return secrets

    def _is_false_positive(self, value):
        """Check if value is likely a false positive"""
        false_positives = [
            'your_', 'example', 'sample', 'test', 'demo',
            'placeholder', 'changeme', '****', '****',
            'xxxxxxxx', 'abcdefgh', '12345678',
            '<', '>', '[', ']', '{', '}',
        ]

        value_lower = value.lower()

        for fp in false_positives:
            if fp in value_lower:
                return True

        # Check if it's a variable name or placeholder
        if value.startswith('$') or value.startswith('${'):
            return True

        return False

    def scan_url_response(self, response_text, url):
        """Scan HTTP response for exposed keys"""
        keys = self.scan_text(response_text)

        for key in keys:
            key['source'] = 'http_response'
            key['url'] = url

        return keys

    def scan_git_history(self, repo_path):
        """Scan git history for exposed keys (requires git)"""
        # This would require git commands - placeholder for future implementation
        self.logger.warning("Git history scanning not yet implemented")
        return []

    def generate_report(self, found_keys):
        """Generate report of found keys"""
        report = {
            'total_keys': len(found_keys),
            'by_provider': {},
            'by_type': {},
            'high_risk_keys': []
        }

        for key in found_keys:
            provider = key.get('provider', 'unknown')
            key_type = key.get('service', key.get('type', 'unknown'))

            # Count by provider
            if provider not in report['by_provider']:
                report['by_provider'][provider] = 0
            report['by_provider'][provider] += 1

            # Count by type
            if key_type not in report['by_type']:
                report['by_type'][key_type] = 0
            report['by_type'][key_type] += 1

            # Identify high-risk keys
            high_risk_types = [
                'aws', 'azure', 'gcp',
                'private_key', 'stripe',
                'database_password', 'connection_string'
            ]

            if provider in high_risk_types or key_type in high_risk_types:
                report['high_risk_keys'].append(key)

        return report
