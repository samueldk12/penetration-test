#!/usr/bin/env python3
"""
Reconnaissance Integration Tool
Integra scanner de secrets, testes de permissão e armazenamento
"""

import sys
import json
from typing import List, Dict, Optional
from pathlib import Path

# Importa componentes locais
from secret_scanner import SecretScanner, SecretPattern
from permission_tester import (
    AWSPermissionTester,
    GCPPermissionTester,
    AzurePermissionTester,
    PermissionTestResult
)
from discovery_storage import DiscoveryDatabase


class ReconIntegration:
    """Integração completa de reconnaissance."""

    def __init__(self, db_path: str = "recon_discoveries.db"):
        self.scanner = SecretScanner()
        self.db = DiscoveryDatabase(db_path)
        self.auto_test_permissions = True

    def scan_and_store_directory(self, directory: str, extensions: Optional[List[str]] = None) -> Dict:
        """
        Escaneia diretório, testa permissões e armazena no banco.

        Args:
            directory: Diretório para escanear
            extensions: Extensões de arquivo (opcional)

        Returns:
            Relatório com estatísticas
        """
        print(f"[*] Escaneando diretório: {directory}")

        # Escaneia secrets
        findings = self.scanner.scan_directory(directory, extensions=extensions)

        print(f"[+] {len(findings)} secrets encontradas!")

        # Armazena no banco e testa permissões
        results = {
            'secrets_found': len(findings),
            'secrets_stored': 0,
            'permissions_tested': 0,
            'high_risk_keys': 0,
            'by_service': {}
        }

        for finding in findings:
            # Armazena secret
            secret_id = self.db.add_secret(
                secret_value=finding['value'],
                secret_type=finding['type'],
                service=finding['service'],
                risk_level=finding['risk_level'],
                discovered_by='secret_scanner',
                notes=f"Found in: {finding['source']}"
            )

            results['secrets_stored'] += 1

            # Conta por serviço
            service = finding['service']
            results['by_service'][service] = results['by_service'].get(service, 0) + 1

            # Testa permissões se for cloud key
            if self.auto_test_permissions and service in ['aws', 'gcp', 'azure']:
                print(f"\n[*] Testando permissões para {finding['type']}...")

                test_result = self._test_cloud_key(finding)

                if test_result and test_result.success:
                    # Armazena resultado do teste
                    self.db.add_permission_test(
                        secret_id=secret_id,
                        test_type=test_result.test_type,
                        test_result='success' if test_result.success else 'failed',
                        permissions_found=test_result.permissions_found,
                        risk_assessment=test_result.risk_assessment
                    )

                    results['permissions_tested'] += 1

                    if test_result.risk_assessment in ['critical', 'high']:
                        results['high_risk_keys'] += 1

        return results

    def scan_and_store_url(self, url: str, response_text: str,
                          response_headers: Optional[Dict] = None,
                          status_code: Optional[int] = None) -> Dict:
        """
        Escaneia resposta HTTP, testa permissões e armazena.

        Args:
            url: URL da requisição
            response_text: Corpo da resposta
            response_headers: Headers da resposta (opcional)
            status_code: Código de status HTTP (opcional)

        Returns:
            Relatório com estatísticas
        """
        print(f"[*] Escaneando URL: {url}")

        # Extrai domínio
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc

        # Armazena URL no banco
        url_id = self.db.add_url(
            url=url,
            domain=domain,
            status_code=status_code,
            headers=response_headers,
            discovered_by='url_scanner'
        )

        # Escaneia secrets na resposta
        findings = self.scanner.scan_url_response(url, response_text, response_headers)

        print(f"[+] {len(findings)} secrets encontradas na resposta!")

        results = {
            'url_id': url_id,
            'secrets_found': len(findings),
            'secrets_stored': 0,
            'permissions_tested': 0,
            'high_risk_keys': 0
        }

        for finding in findings:
            # Armazena secret vinculada à URL
            secret_id = self.db.add_secret(
                secret_value=finding['value'],
                secret_type=finding['type'],
                url=url,
                service=finding['service'],
                risk_level=finding['risk_level'],
                discovered_by='url_scanner',
                notes=f"Found in HTTP response: {url}"
            )

            results['secrets_stored'] += 1

            # Testa permissões
            if self.auto_test_permissions and finding['service'] in ['aws', 'gcp', 'azure']:
                print(f"\n[*] Testando permissões para {finding['type']}...")

                test_result = self._test_cloud_key(finding)

                if test_result and test_result.success:
                    self.db.add_permission_test(
                        secret_id=secret_id,
                        test_type=test_result.test_type,
                        test_result='success' if test_result.success else 'failed',
                        permissions_found=test_result.permissions_found,
                        risk_assessment=test_result.risk_assessment
                    )

                    results['permissions_tested'] += 1

                    if test_result.risk_assessment in ['critical', 'high']:
                        results['high_risk_keys'] += 1

        return results

    def _test_cloud_key(self, finding: Dict) -> Optional[PermissionTestResult]:
        """
        Testa permissões de cloud key.

        Args:
            finding: Finding do scanner

        Returns:
            Resultado do teste ou None
        """
        service = finding['service']
        secret_type = finding['type']
        secret_value = finding['value']

        try:
            # AWS
            if service == 'aws':
                if secret_type == 'AWS Access Key ID':
                    # Precisamos da secret key também
                    print("[!] AWS Access Key encontrada, mas Secret Key é necessária para teste")
                    return None

                # Se temos ambas as keys, podemos testar
                # (Esta lógica seria expandida para buscar pares de keys)
                return None

            # GCP
            elif service == 'gcp':
                if secret_type == 'GCP Service Account':
                    tester = GCPPermissionTester(credentials_json=secret_value)
                    return tester.test_permissions()

                elif secret_type == 'GCP API Key':
                    # API Keys GCP são mais limitadas, teste específico
                    print("[!] GCP API Key encontrada - teste limitado disponível")
                    return None

            # Azure
            elif service == 'azure':
                if secret_type == 'Azure Connection String':
                    tester = AzurePermissionTester(connection_string=secret_value)
                    return tester.test_permissions()

                elif secret_type == 'Azure Storage Account Key':
                    # Precisamos do account name também
                    print("[!] Azure Storage Key encontrada, mas Account Name é necessário para teste")
                    return None

        except Exception as e:
            print(f"[!] Erro ao testar permissões: {e}")

        return None

    def test_aws_key_pair(self, access_key_id: str, secret_access_key: str,
                         session_token: Optional[str] = None) -> Dict:
        """
        Testa par de keys AWS e armazena resultado.

        Args:
            access_key_id: AWS Access Key ID
            secret_access_key: AWS Secret Access Key
            session_token: AWS Session Token (opcional)

        Returns:
            Resultado do teste
        """
        print(f"[*] Testando AWS credentials: {access_key_id[:10]}...")

        # Armazena secret
        secret_id = self.db.add_secret(
            secret_value=f"{access_key_id}:{secret_access_key}",
            secret_type='AWS Access Key Pair',
            service='aws',
            risk_level='critical',
            discovered_by='manual',
            notes='AWS key pair for permission testing'
        )

        # Testa permissões
        tester = AWSPermissionTester(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token
        )

        result = tester.test_permissions()

        # Armazena resultado
        if result.success:
            self.db.add_permission_test(
                secret_id=secret_id,
                test_type=result.test_type,
                test_result='success',
                permissions_found=result.permissions_found,
                risk_assessment=result.risk_assessment
            )

        return result.to_dict()

    def test_gcp_service_account(self, credentials_json: str) -> Dict:
        """
        Testa Service Account GCP e armazena resultado.

        Args:
            credentials_json: Service Account JSON (string ou path)

        Returns:
            Resultado do teste
        """
        print(f"[*] Testando GCP Service Account...")

        # Armazena secret
        secret_id = self.db.add_secret(
            secret_value=credentials_json,
            secret_type='GCP Service Account',
            service='gcp',
            risk_level='critical',
            discovered_by='manual',
            notes='GCP service account for permission testing'
        )

        # Testa permissões
        tester = GCPPermissionTester(credentials_json=credentials_json)
        result = tester.test_permissions()

        # Armazena resultado
        if result.success:
            self.db.add_permission_test(
                secret_id=secret_id,
                test_type=result.test_type,
                test_result='success',
                permissions_found=result.permissions_found,
                risk_assessment=result.risk_assessment
            )

        return result.to_dict()

    def test_azure_storage(self, connection_string: Optional[str] = None,
                          account_name: Optional[str] = None,
                          account_key: Optional[str] = None) -> Dict:
        """
        Testa Azure Storage e armazena resultado.

        Args:
            connection_string: Connection string completa
            account_name: Nome da storage account
            account_key: Key da storage account

        Returns:
            Resultado do teste
        """
        print(f"[*] Testando Azure Storage...")

        # Armazena secret
        secret_value = connection_string if connection_string else f"{account_name}:{account_key}"

        secret_id = self.db.add_secret(
            secret_value=secret_value,
            secret_type='Azure Storage Credentials',
            service='azure',
            risk_level='critical',
            discovered_by='manual',
            notes='Azure storage credentials for permission testing'
        )

        # Testa permissões
        tester = AzurePermissionTester(
            connection_string=connection_string,
            account_name=account_name,
            account_key=account_key
        )

        result = tester.test_permissions()

        # Armazena resultado
        if result.success:
            self.db.add_permission_test(
                secret_id=secret_id,
                test_type=result.test_type,
                test_result='success',
                permissions_found=result.permissions_found,
                risk_assessment=result.risk_assessment
            )

        return result.to_dict()

    def get_high_risk_secrets(self) -> List[Dict]:
        """
        Retorna secrets de alto risco com resultados de testes.

        Returns:
            Lista de secrets de alto risco
        """
        # Busca secrets não testadas
        untested = self.db.get_secrets(untested_only=True)

        # Busca secrets testadas
        all_secrets = self.db.get_secrets()

        high_risk = []

        for secret in all_secrets:
            # Filtra por risco
            if secret['risk_level'] in ['critical', 'high']:
                high_risk.append(secret)

        return high_risk

    def generate_report(self, output_file: str = "recon_report.json"):
        """
        Gera relatório completo de reconnaissance.

        Args:
            output_file: Arquivo de saída JSON
        """
        print(f"[*] Gerando relatório...")

        stats = self.db.get_statistics()

        report = {
            'statistics': stats,
            'high_risk_secrets': self.get_high_risk_secrets(),
            'untested_secrets': self.db.get_secrets(untested_only=True),
            'urls': self.db.get_urls(),
            'subdomains': self.db.get_subdomains()
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[+] Relatório salvo em: {output_file}")

        # Mostra resumo
        print("\n=== RESUMO DO RECONNAISSANCE ===")
        print(f"Total de URLs: {stats['total_urls']}")
        print(f"Total de Secrets: {stats['total_secrets']}")
        print(f"Secrets Testadas: {stats['secrets_tested']}")
        print(f"Subdomínios: {stats['total_subdomains']}")
        print(f"Endpoints: {stats['total_endpoints']}")

        if stats['secrets_by_type']:
            print("\nSecrets por tipo:")
            for secret_type, count in sorted(stats['secrets_by_type'].items(),
                                            key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {secret_type}: {count}")

        high_risk_count = len(report['high_risk_secrets'])
        if high_risk_count > 0:
            print(f"\n[!] {high_risk_count} secrets de ALTO RISCO encontradas!")

    def close(self):
        """Fecha conexão com banco de dados."""
        self.db.close()


# CLI Interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Recon Integration - Scanner + Tester + Storage")
    subparsers = parser.add_subparsers(dest='command', help='Command')

    # Scan directory
    scan_parser = subparsers.add_parser('scan', help='Scan directory for secrets')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('-e', '--extensions', nargs='+', help='File extensions')
    scan_parser.add_argument('--no-test', action='store_true', help='Skip permission testing')

    # Test AWS
    aws_parser = subparsers.add_parser('test-aws', help='Test AWS credentials')
    aws_parser.add_argument('--access-key', required=True, help='AWS Access Key ID')
    aws_parser.add_argument('--secret-key', required=True, help='AWS Secret Access Key')
    aws_parser.add_argument('--session-token', help='AWS Session Token')

    # Test GCP
    gcp_parser = subparsers.add_parser('test-gcp', help='Test GCP credentials')
    gcp_parser.add_argument('--credentials', required=True, help='Service Account JSON')

    # Test Azure
    azure_parser = subparsers.add_parser('test-azure', help='Test Azure credentials')
    azure_parser.add_argument('--connection-string', help='Connection String')
    azure_parser.add_argument('--account-name', help='Storage Account Name')
    azure_parser.add_argument('--account-key', help='Storage Account Key')

    # Report
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('-o', '--output', default='recon_report.json', help='Output file')

    # Database
    parser.add_argument('--db', default='recon_discoveries.db', help='Database file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Inicializa integração
    recon = ReconIntegration(db_path=args.db)

    try:
        if args.command == 'scan':
            recon.auto_test_permissions = not args.no_test
            results = recon.scan_and_store_directory(args.directory, extensions=args.extensions)

            print("\n=== RESULTADOS ===")
            print(f"Secrets encontradas: {results['secrets_found']}")
            print(f"Secrets armazenadas: {results['secrets_stored']}")
            print(f"Permissões testadas: {results['permissions_tested']}")
            print(f"Keys de alto risco: {results['high_risk_keys']}")

        elif args.command == 'test-aws':
            result = recon.test_aws_key_pair(
                access_key_id=args.access_key,
                secret_access_key=args.secret_key,
                session_token=args.session_token
            )
            print(json.dumps(result, indent=2))

        elif args.command == 'test-gcp':
            result = recon.test_gcp_service_account(credentials_json=args.credentials)
            print(json.dumps(result, indent=2))

        elif args.command == 'test-azure':
            if not (args.connection_string or (args.account_name and args.account_key)):
                print("[!] Erro: Forneça --connection-string OU (--account-name E --account-key)")
                sys.exit(1)

            result = recon.test_azure_storage(
                connection_string=args.connection_string,
                account_name=args.account_name,
                account_key=args.account_key
            )
            print(json.dumps(result, indent=2))

        elif args.command == 'report':
            recon.generate_report(output_file=args.output)

    finally:
        recon.close()
