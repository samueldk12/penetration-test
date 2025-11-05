#!/usr/bin/env python3
"""
Secret Scanner - Detecção de API Keys e Cloud Credentials
Detecta secrets em código-fonte, páginas web, arquivos de configuração
"""

import re
import hashlib
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import json


class SecretPattern:
    """Representa um padrão de secret com regex e metadados."""

    def __init__(self, name: str, pattern: str, service: str,
                 risk_level: str = "high", description: str = ""):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.service = service
        self.risk_level = risk_level
        self.description = description


class SecretScanner:
    """Scanner de secrets e API keys."""

    def __init__(self):
        self.patterns = self._init_patterns()
        self.findings = []

    def _init_patterns(self) -> List[SecretPattern]:
        """Inicializa padrões de detecção de secrets."""

        patterns = []

        # ============================================
        # AWS CREDENTIALS
        # ============================================

        # AWS Access Key ID
        patterns.append(SecretPattern(
            name="AWS Access Key ID",
            pattern=r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            service="aws",
            risk_level="critical",
            description="AWS Access Key ID - permite acesso aos recursos AWS"
        ))

        # AWS Secret Access Key
        patterns.append(SecretPattern(
            name="AWS Secret Access Key",
            pattern=r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z\/+]{40}[\'"]',
            service="aws",
            risk_level="critical",
            description="AWS Secret Access Key"
        ))

        # AWS Account ID
        patterns.append(SecretPattern(
            name="AWS Account ID",
            pattern=r'(?:aws_account_id|aws.{0,10}account.{0,10}id).{0,20}[\'"]?[0-9]{12}[\'"]?',
            service="aws",
            risk_level="medium",
            description="AWS Account ID"
        ))

        # AWS Session Token
        patterns.append(SecretPattern(
            name="AWS Session Token",
            pattern=r'(?i)aws.{0,20}session.{0,20}token.{0,20}[\'"][a-zA-Z0-9/+=]{100,}[\'"]',
            service="aws",
            risk_level="high",
            description="AWS Session Token"
        ))

        # ============================================
        # GOOGLE CLOUD PLATFORM (GCP)
        # ============================================

        # GCP API Key
        patterns.append(SecretPattern(
            name="GCP API Key",
            pattern=r'AIza[0-9A-Za-z\-_]{35}',
            service="gcp",
            risk_level="critical",
            description="Google Cloud Platform API Key"
        ))

        # GCP OAuth 2.0 Client ID
        patterns.append(SecretPattern(
            name="GCP OAuth Client ID",
            pattern=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            service="gcp",
            risk_level="high",
            description="Google OAuth 2.0 Client ID"
        ))

        # GCP Service Account JSON (complete structure)
        patterns.append(SecretPattern(
            name="GCP Service Account",
            pattern=r'\{[^}]*"type"\s*:\s*"service_account"[^}]*"project_id"[^}]*"private_key"[^}]*\}',
            service="gcp",
            risk_level="critical",
            description="GCP Service Account JSON completo"
        ))

        # GCP Private Key
        patterns.append(SecretPattern(
            name="GCP Private Key",
            pattern=r'-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\n\+\/=]{100,}-----END PRIVATE KEY-----',
            service="gcp",
            risk_level="critical",
            description="GCP Private Key"
        ))

        # ============================================
        # MICROSOFT AZURE
        # ============================================

        # Azure Storage Account Key
        patterns.append(SecretPattern(
            name="Azure Storage Account Key",
            pattern=r'(?i)(?:storage|azure).{0,20}(?:key|account).{0,20}[\'"][a-zA-Z0-9+/=]{88}[\'"]',
            service="azure",
            risk_level="critical",
            description="Azure Storage Account Key"
        ))

        # Azure Connection String
        patterns.append(SecretPattern(
            name="Azure Connection String",
            pattern=r'DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[a-zA-Z0-9+/=]{88};',
            service="azure",
            risk_level="critical",
            description="Azure Storage Connection String"
        ))

        # Azure Client Secret
        patterns.append(SecretPattern(
            name="Azure Client Secret",
            pattern=r'(?i)client.{0,20}secret.{0,20}[\'"][a-zA-Z0-9\-_~\.]{34,40}[\'"]',
            service="azure",
            risk_level="high",
            description="Azure Application Client Secret"
        ))

        # Azure Tenant ID
        patterns.append(SecretPattern(
            name="Azure Tenant ID",
            pattern=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            service="azure",
            risk_level="low",
            description="Azure Tenant/Application ID"
        ))

        # ============================================
        # DIGITALOCEAN
        # ============================================

        # DigitalOcean Personal Access Token
        patterns.append(SecretPattern(
            name="DigitalOcean Token",
            pattern=r'(?i)digitalocean.{0,20}token.{0,20}[\'"][a-f0-9]{64}[\'"]',
            service="digitalocean",
            risk_level="critical",
            description="DigitalOcean Personal Access Token"
        ))

        # ============================================
        # GITHUB
        # ============================================

        # GitHub Personal Access Token (classic)
        patterns.append(SecretPattern(
            name="GitHub PAT (classic)",
            pattern=r'ghp_[a-zA-Z0-9]{36}',
            service="github",
            risk_level="high",
            description="GitHub Personal Access Token (classic)"
        ))

        # GitHub OAuth Access Token
        patterns.append(SecretPattern(
            name="GitHub OAuth Token",
            pattern=r'gho_[a-zA-Z0-9]{36}',
            service="github",
            risk_level="high",
            description="GitHub OAuth Access Token"
        ))

        # GitHub App Token
        patterns.append(SecretPattern(
            name="GitHub App Token",
            pattern=r'(?:ghu|ghs)_[a-zA-Z0-9]{36}',
            service="github",
            risk_level="high",
            description="GitHub App Token"
        ))

        # GitHub Refresh Token
        patterns.append(SecretPattern(
            name="GitHub Refresh Token",
            pattern=r'ghr_[a-zA-Z0-9]{76}',
            service="github",
            risk_level="high",
            description="GitHub Refresh Token"
        ))

        # ============================================
        # GITLAB
        # ============================================

        # GitLab Personal Access Token
        patterns.append(SecretPattern(
            name="GitLab PAT",
            pattern=r'glpat-[a-zA-Z0-9\-_]{20}',
            service="gitlab",
            risk_level="high",
            description="GitLab Personal Access Token"
        ))

        # ============================================
        # SLACK
        # ============================================

        # Slack Webhook URL
        patterns.append(SecretPattern(
            name="Slack Webhook",
            pattern=r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            service="slack",
            risk_level="medium",
            description="Slack Webhook URL"
        ))

        # Slack API Token
        patterns.append(SecretPattern(
            name="Slack Token",
            pattern=r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
            service="slack",
            risk_level="high",
            description="Slack API Token"
        ))

        # ============================================
        # STRIPE
        # ============================================

        # Stripe Secret Key
        patterns.append(SecretPattern(
            name="Stripe Secret Key",
            pattern=r'sk_live_[0-9a-zA-Z]{24,99}',
            service="stripe",
            risk_level="critical",
            description="Stripe Secret Key (LIVE)"
        ))

        # Stripe Restricted Key
        patterns.append(SecretPattern(
            name="Stripe Restricted Key",
            pattern=r'rk_live_[0-9a-zA-Z]{24,99}',
            service="stripe",
            risk_level="high",
            description="Stripe Restricted Key (LIVE)"
        ))

        # Stripe Test Key (lower risk)
        patterns.append(SecretPattern(
            name="Stripe Test Key",
            pattern=r'sk_test_[0-9a-zA-Z]{24,99}',
            service="stripe",
            risk_level="low",
            description="Stripe Secret Key (TEST)"
        ))

        # ============================================
        # SENDGRID
        # ============================================

        # SendGrid API Key
        patterns.append(SecretPattern(
            name="SendGrid API Key",
            pattern=r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            service="sendgrid",
            risk_level="high",
            description="SendGrid API Key"
        ))

        # ============================================
        # TWILIO
        # ============================================

        # Twilio API Key
        patterns.append(SecretPattern(
            name="Twilio API Key",
            pattern=r'SK[a-z0-9]{32}',
            service="twilio",
            risk_level="high",
            description="Twilio API Key"
        ))

        # Twilio Account SID
        patterns.append(SecretPattern(
            name="Twilio Account SID",
            pattern=r'AC[a-z0-9]{32}',
            service="twilio",
            risk_level="medium",
            description="Twilio Account SID"
        ))

        # ============================================
        # MAILGUN
        # ============================================

        # Mailgun API Key
        patterns.append(SecretPattern(
            name="Mailgun API Key",
            pattern=r'key-[a-zA-Z0-9]{32}',
            service="mailgun",
            risk_level="high",
            description="Mailgun API Key"
        ))

        # ============================================
        # HEROKU
        # ============================================

        # Heroku API Key
        patterns.append(SecretPattern(
            name="Heroku API Key",
            pattern=r'(?i)heroku.{0,20}[\'"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[\'"]',
            service="heroku",
            risk_level="high",
            description="Heroku API Key"
        ))

        # ============================================
        # FACEBOOK
        # ============================================

        # Facebook Access Token
        patterns.append(SecretPattern(
            name="Facebook Access Token",
            pattern=r'EAACEdEose0cBA[0-9A-Za-z]+',
            service="facebook",
            risk_level="high",
            description="Facebook Access Token"
        ))

        # ============================================
        # TWITTER
        # ============================================

        # Twitter API Key
        patterns.append(SecretPattern(
            name="Twitter API Key",
            pattern=r'(?i)twitter.{0,20}[\'"][0-9a-zA-Z]{35,44}[\'"]',
            service="twitter",
            risk_level="high",
            description="Twitter API Key"
        ))

        # Twitter Access Token
        patterns.append(SecretPattern(
            name="Twitter Access Token",
            pattern=r'[0-9]{15,22}-[0-9a-zA-Z]{35,44}',
            service="twitter",
            risk_level="high",
            description="Twitter Access Token"
        ))

        # ============================================
        # GENERIC PATTERNS
        # ============================================

        # Generic API Key
        patterns.append(SecretPattern(
            name="Generic API Key",
            pattern=r'(?i)(?:api[_-]?key|apikey|api[_-]?secret).{0,20}[\'"][a-zA-Z0-9_\-]{16,64}[\'"]',
            service="generic",
            risk_level="medium",
            description="Generic API Key"
        ))

        # Generic Secret/Token
        patterns.append(SecretPattern(
            name="Generic Secret",
            pattern=r'(?i)(?:secret|token|password|passwd|pwd).{0,20}[\'"][a-zA-Z0-9_\-!@#$%^&*()+=]{12,64}[\'"]',
            service="generic",
            risk_level="medium",
            description="Generic Secret/Token"
        ))

        # RSA Private Key
        patterns.append(SecretPattern(
            name="RSA Private Key",
            pattern=r'-----BEGIN (?:RSA )?PRIVATE KEY-----[a-zA-Z0-9\n\+\/=]{100,}-----END (?:RSA )?PRIVATE KEY-----',
            service="generic",
            risk_level="critical",
            description="RSA Private Key"
        ))

        # SSH Private Key (DSA)
        patterns.append(SecretPattern(
            name="DSA Private Key",
            pattern=r'-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9\n\+\/=]{100,}-----END DSA PRIVATE KEY-----',
            service="generic",
            risk_level="critical",
            description="DSA Private Key"
        ))

        # EC Private Key
        patterns.append(SecretPattern(
            name="EC Private Key",
            pattern=r'-----BEGIN EC PRIVATE KEY-----[a-zA-Z0-9\n\+\/=]{100,}-----END EC PRIVATE KEY-----',
            service="generic",
            risk_level="critical",
            description="EC Private Key"
        ))

        # OpenSSH Private Key
        patterns.append(SecretPattern(
            name="OpenSSH Private Key",
            pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9\n\+\/=]{100,}-----END OPENSSH PRIVATE KEY-----',
            service="generic",
            risk_level="critical",
            description="OpenSSH Private Key"
        ))

        # Database Connection String
        patterns.append(SecretPattern(
            name="Database Connection String",
            pattern=r'(?i)(?:mysql|postgres|mongodb|redis)://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*()+=]+@[a-zA-Z0-9\.\-]+(?::[0-9]+)?',
            service="database",
            risk_level="critical",
            description="Database Connection String with credentials"
        ))

        # JWT Token
        patterns.append(SecretPattern(
            name="JWT Token",
            pattern=r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',
            service="generic",
            risk_level="medium",
            description="JSON Web Token (JWT)"
        ))

        return patterns

    def scan_text(self, text: str, source: str = "unknown") -> List[Dict]:
        """
        Escaneia texto em busca de secrets.

        Args:
            text: Texto para escanear
            source: Origem do texto (URL, arquivo, etc.)

        Returns:
            Lista de findings com secrets encontradas
        """
        findings = []

        for pattern in self.patterns:
            matches = pattern.pattern.finditer(text)

            for match in matches:
                secret_value = match.group(0)

                # Hash da secret para storage
                secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()

                # Extrai contexto (50 chars antes e depois)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                finding = {
                    'type': pattern.name,
                    'service': pattern.service,
                    'risk_level': pattern.risk_level,
                    'value': secret_value,
                    'hash': secret_hash,
                    'description': pattern.description,
                    'source': source,
                    'context': context,
                    'position': {
                        'start': match.start(),
                        'end': match.end()
                    }
                }

                findings.append(finding)

        return findings

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Escaneia arquivo em busca de secrets.

        Args:
            file_path: Caminho do arquivo

        Returns:
            Lista de findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            return self.scan_text(content, source=f"file://{file_path}")

        except Exception as e:
            print(f"[!] Erro ao escanear {file_path}: {e}")
            return []

    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[Dict]:
        """
        Escaneia diretório recursivamente em busca de secrets.

        Args:
            directory: Diretório raiz
            extensions: Lista de extensões para filtrar (ex: ['.py', '.js', '.env'])

        Returns:
            Lista de findings
        """
        all_findings = []

        path = Path(directory)

        # Extensões padrão se não especificadas
        if extensions is None:
            extensions = [
                '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb',
                '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cs', '.swift',
                '.env', '.config', '.conf', '.yaml', '.yml', '.json', '.xml',
                '.properties', '.ini', '.toml', '.sh', '.bash', '.zsh',
                '.txt', '.md', '.log'
            ]

        # Diretórios a ignorar
        ignore_dirs = {
            '.git', '.svn', '.hg', 'node_modules', 'venv', 'env',
            '__pycache__', '.pytest_cache', 'dist', 'build', 'target'
        }

        for file_path in path.rglob('*'):
            # Ignora diretórios especiais
            if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                continue

            # Verifica extensão
            if file_path.is_file() and file_path.suffix in extensions:
                findings = self.scan_file(str(file_path))
                all_findings.extend(findings)

        return all_findings

    def scan_url_response(self, url: str, response_text: str,
                         response_headers: Dict = None) -> List[Dict]:
        """
        Escaneia resposta HTTP em busca de secrets.

        Args:
            url: URL da requisição
            response_text: Corpo da resposta
            response_headers: Headers da resposta (opcional)

        Returns:
            Lista de findings
        """
        findings = []

        # Escaneia corpo da resposta
        body_findings = self.scan_text(response_text, source=f"http://{url}")
        findings.extend(body_findings)

        # Escaneia headers se fornecidos
        if response_headers:
            headers_text = json.dumps(response_headers)
            header_findings = self.scan_text(headers_text, source=f"http_headers://{url}")
            findings.extend(header_findings)

        return findings

    def generate_report(self, findings: List[Dict]) -> Dict:
        """
        Gera relatório estatístico dos findings.

        Args:
            findings: Lista de findings

        Returns:
            Dicionário com estatísticas
        """
        report = {
            'total_secrets': len(findings),
            'by_service': {},
            'by_risk_level': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'by_type': {},
            'sources': set()
        }

        for finding in findings:
            # Count by service
            service = finding['service']
            report['by_service'][service] = report['by_service'].get(service, 0) + 1

            # Count by risk level
            risk = finding['risk_level']
            report['by_risk_level'][risk] += 1

            # Count by type
            secret_type = finding['type']
            report['by_type'][secret_type] = report['by_type'].get(secret_type, 0) + 1

            # Add source
            report['sources'].add(finding['source'])

        # Convert set to list for JSON serialization
        report['sources'] = list(report['sources'])

        return report

    def print_findings(self, findings: List[Dict], verbose: bool = False):
        """
        Imprime findings formatados.

        Args:
            findings: Lista de findings
            verbose: Se True, mostra contexto completo
        """
        if not findings:
            print("[*] Nenhuma secret encontrada.")
            return

        print(f"\n[+] {len(findings)} secrets encontradas!\n")

        for i, finding in enumerate(findings, 1):
            risk_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(finding['risk_level'], '⚪')

            print(f"{risk_emoji} Finding #{i}")
            print(f"   Tipo: {finding['type']}")
            print(f"   Serviço: {finding['service']}")
            print(f"   Risco: {finding['risk_level'].upper()}")
            print(f"   Valor: {finding['value'][:50]}..." if len(finding['value']) > 50 else f"   Valor: {finding['value']}")
            print(f"   Hash: {finding['hash'][:16]}...")
            print(f"   Fonte: {finding['source']}")

            if verbose:
                print(f"   Contexto: ...{finding['context']}...")

            print()

        # Relatório resumido
        report = self.generate_report(findings)
        print("\n=== RESUMO ===")
        print(f"Total de secrets: {report['total_secrets']}")
        print(f"\nPor nível de risco:")
        for level, count in sorted(report['by_risk_level'].items(),
                                   key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x[0]]):
            if count > 0:
                print(f"  {level.upper()}: {count}")

        print(f"\nPor serviço:")
        for service, count in sorted(report['by_service'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {service}: {count}")


# CLI Interface
if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Secret Scanner - Detecta API keys e credentials")
    parser.add_argument('target', help="Arquivo ou diretório para escanear")
    parser.add_argument('-v', '--verbose', action='store_true', help="Mostra contexto completo")
    parser.add_argument('-e', '--extensions', nargs='+', help="Extensões de arquivo para escanear")
    parser.add_argument('-o', '--output', help="Arquivo JSON para salvar findings")

    args = parser.parse_args()

    scanner = SecretScanner()

    # Determina se é arquivo ou diretório
    target_path = Path(args.target)

    if target_path.is_file():
        findings = scanner.scan_file(str(target_path))
    elif target_path.is_dir():
        findings = scanner.scan_directory(str(target_path), extensions=args.extensions)
    else:
        print(f"[!] Target não encontrado: {args.target}")
        sys.exit(1)

    # Mostra findings
    scanner.print_findings(findings, verbose=args.verbose)

    # Salva em JSON se especificado
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] Findings salvos em: {args.output}")
