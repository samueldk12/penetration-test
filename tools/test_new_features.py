#!/usr/bin/env python3
"""
Test Suite for New Features
Testes para novos plugins, OSINT module e Advanced Reporter
"""

import unittest
import sys
import tempfile
import os
from pathlib import Path

# Adiciona path dos tools
sys.path.insert(0, str(Path(__file__).parent))

from plugin_system import PluginManager
from discovery_storage import DiscoveryDatabase
from advanced_reporter import AdvancedReporter
from osint_module import OSINTModule


class TestNewPlugins(unittest.TestCase):
    """Testa novos plugins de recon e vulnerability scanning."""

    def setUp(self):
        """Configura ambiente de teste."""
        self.plugin_manager = PluginManager()
        self.plugin_manager.discover_plugins()

    def test_nikto_plugin_exists(self):
        """Verifica se plugin Nikto foi registrado."""
        self.assertIn('nikto_scanner', self.plugin_manager.plugins)

    def test_nuclei_plugin_exists(self):
        """Verifica se plugin Nuclei foi registrado."""
        self.assertIn('nuclei_scanner', self.plugin_manager.plugins)

    def test_nmap_plugin_exists(self):
        """Verifica se plugin Nmap foi registrado."""
        self.assertIn('nmap_scanner', self.plugin_manager.plugins)

    def test_ffuf_plugin_exists(self):
        """Verifica se plugin FFUF foi registrado."""
        self.assertIn('ffuf_fuzzer', self.plugin_manager.plugins)

    def test_katana_plugin_exists(self):
        """Verifica se plugin Katana foi registrado."""
        self.assertIn('katana_crawler', self.plugin_manager.plugins)

    def test_dalfox_plugin_exists(self):
        """Verifica se plugin Dalfox foi registrado."""
        self.assertIn('dalfox_xss', self.plugin_manager.plugins)

    def test_subdominator_plugin_exists(self):
        """Verifica se plugin Subdominator foi registrado."""
        self.assertIn('subdominator', self.plugin_manager.plugins)

    def test_dnsbruter_plugin_exists(self):
        """Verifica se plugin DNSBruter foi registrado."""
        self.assertIn('dnsbruter', self.plugin_manager.plugins)

    def test_plugin_categories(self):
        """Verifica categorias dos plugins."""
        recon_plugins = self.plugin_manager.get_plugins_by_category('recon')
        vuln_plugins = self.plugin_manager.get_plugins_by_category('vuln_scan')

        # Deve ter pelo menos os novos plugins de recon
        recon_names = [p.name for p in recon_plugins]
        self.assertIn('nmap_scanner', recon_names)
        self.assertIn('ffuf_fuzzer', recon_names)
        self.assertIn('katana_crawler', recon_names)
        self.assertIn('subdominator', recon_names)
        self.assertIn('dnsbruter', recon_names)

        # Deve ter novos plugins de vuln_scan
        vuln_names = [p.name for p in vuln_plugins]
        self.assertIn('nikto_scanner', vuln_names)
        self.assertIn('nuclei_scanner', vuln_names)
        self.assertIn('dalfox_xss', vuln_names)


class TestDiscoveryDatabase(unittest.TestCase):
    """Testa melhorias no banco de dados."""

    def setUp(self):
        """Cria banco de dados temporário."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db = DiscoveryDatabase(self.temp_db.name)

    def tearDown(self):
        """Limpa banco de dados temporário."""
        self.db.close()
        os.unlink(self.temp_db.name)

    def test_add_vulnerability(self):
        """Testa adição de vulnerabilidade."""
        vuln_id = self.db.add_vulnerability(
            'xss',
            'high',
            description='Reflected XSS found',
            payload='<script>alert(1)</script>',
            discovered_by='test_scanner'
        )

        self.assertIsInstance(vuln_id, int)
        self.assertGreater(vuln_id, 0)

    def test_get_vulnerabilities(self):
        """Testa recuperação de vulnerabilidades."""
        # Adiciona algumas vulnerabilidades
        self.db.add_vulnerability('xss', 'high', description='XSS 1')
        self.db.add_vulnerability('sqli', 'critical', description='SQLi 1')
        self.db.add_vulnerability('xss', 'medium', description='XSS 2')

        # Busca todas
        all_vulns = self.db.get_vulnerabilities()
        self.assertEqual(len(all_vulns), 3)

        # Busca por tipo
        xss_vulns = self.db.get_vulnerabilities(vuln_type='xss')
        self.assertEqual(len(xss_vulns), 2)

        # Busca por severidade
        critical_vulns = self.db.get_vulnerabilities(severity='critical')
        self.assertEqual(len(critical_vulns), 1)

    def test_vulnerability_table_structure(self):
        """Verifica estrutura da tabela de vulnerabilidades."""
        cursor = self.db.conn.cursor()

        # Verifica se tabela existe
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='vulnerabilities'
        """)
        self.assertIsNotNone(cursor.fetchone())

        # Verifica colunas esperadas
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [row[1] for row in cursor.fetchall()]

        expected_columns = [
            'id', 'url_id', 'endpoint_id', 'vuln_type', 'severity',
            'description', 'payload', 'evidence', 'cvss_score', 'cve_id',
            'discovered_by', 'discovered_at', 'verified', 'false_positive',
            'remediation', 'notes'
        ]

        for col in expected_columns:
            self.assertIn(col, columns)

    def test_statistics_include_vulnerabilities(self):
        """Verifica se estatísticas incluem vulnerabilidades."""
        # Adiciona dados de teste
        self.db.add_vulnerability('xss', 'high')
        self.db.add_vulnerability('sqli', 'critical')
        self.db.add_vulnerability('lfi', 'medium')

        stats = self.db.get_statistics()

        self.assertIn('total_vulnerabilities', stats)
        self.assertEqual(stats['total_vulnerabilities'], 3)

        self.assertIn('vulnerabilities_by_severity', stats)
        self.assertIn('vulnerabilities_by_type', stats)


class TestAdvancedReporter(unittest.TestCase):
    """Testa sistema avançado de relatórios."""

    def setUp(self):
        """Cria banco de dados e reporter temporários."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db = DiscoveryDatabase(self.temp_db.name)
        self.reporter = AdvancedReporter(self.temp_db.name)

        # Popula banco com dados de teste
        self._populate_test_data()

    def tearDown(self):
        """Limpa recursos."""
        self.db.close()
        self.reporter.close()
        os.unlink(self.temp_db.name)

    def _populate_test_data(self):
        """Popula banco com dados de teste."""
        # URLs
        self.db.add_url('https://example.com/api/users', 'example.com',
                       discovered_by='test')

        # Secrets
        self.db.add_secret('AKIA1234567890ABCDEF', 'aws_access_key',
                          service='aws', risk_level='high')
        self.db.add_secret('ya29.1234567890', 'gcp_service_account',
                          service='gcp', risk_level='critical')

        # Vulnerabilidades
        self.db.add_vulnerability('xss', 'high', description='XSS found')
        self.db.add_vulnerability('sqli', 'critical', description='SQLi found')
        self.db.add_vulnerability('lfi', 'medium', description='LFI found')

        # Subdomains
        self.db.add_subdomain('api.example.com', 'example.com')
        self.db.add_subdomain('dev.example.com', 'example.com')

    def test_generate_comprehensive_report(self):
        """Testa geração de relatório abrangente."""
        report = self.reporter.generate_comprehensive_report()

        # Verifica estrutura do relatório
        self.assertIn('metadata', report)
        self.assertIn('executive_summary', report)
        self.assertIn('osint_findings', report)
        self.assertIn('vulnerability_findings', report)
        self.assertIn('api_keys_and_secrets', report)
        self.assertIn('recon_data', report)
        self.assertIn('recommendations', report)

    def test_executive_summary(self):
        """Testa resumo executivo."""
        report = self.reporter.generate_comprehensive_report()
        summary = report['executive_summary']

        self.assertIn('total_urls', summary)
        self.assertIn('total_secrets', summary)
        self.assertIn('total_subdomains', summary)
        self.assertIn('severity_distribution', summary)
        self.assertIn('risk_score', summary)

        # Verifica valores
        self.assertGreaterEqual(summary['total_urls'], 1)
        self.assertGreaterEqual(summary['total_secrets'], 2)
        self.assertGreaterEqual(summary['total_subdomains'], 2)

    def test_api_keys_breakdown(self):
        """Testa breakdown de API keys."""
        report = self.reporter.generate_comprehensive_report()
        secrets = report['api_keys_and_secrets']

        self.assertIn('api_keys_breakdown', secrets)
        breakdown = secrets['api_keys_breakdown']

        self.assertIn('aws_keys', breakdown)
        self.assertIn('gcp_keys', breakdown)
        self.assertEqual(breakdown['aws_keys'], 1)
        self.assertEqual(breakdown['gcp_keys'], 1)

    def test_vulnerability_aggregation(self):
        """Testa agregação de vulnerabilidades."""
        report = self.reporter.generate_comprehensive_report()
        vulns = report['vulnerability_findings']

        self.assertIn('total_count', vulns)
        self.assertIn('by_type', vulns)
        self.assertIn('by_severity', vulns)

        self.assertGreaterEqual(vulns['total_count'], 3)

    def test_filtered_report_vulnerabilities(self):
        """Testa relatório filtrado de vulnerabilidades."""
        report = self.reporter.generate_filtered_report('vulnerabilities')

        self.assertEqual(report['report_type'], 'vulnerabilities')
        self.assertIn('data', report)

    def test_filtered_report_secrets(self):
        """Testa relatório filtrado de secrets."""
        report = self.reporter.generate_filtered_report('secrets')

        self.assertEqual(report['report_type'], 'secrets')
        self.assertIn('data', report)

    def test_recommendations_generation(self):
        """Testa geração de recomendações."""
        report = self.reporter.generate_comprehensive_report()
        recommendations = report['recommendations']

        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)

        # Verifica estrutura das recomendações
        for rec in recommendations:
            self.assertIn('priority', rec)
            self.assertIn('category', rec)
            self.assertIn('title', rec)
            self.assertIn('description', rec)

    def test_export_json_report(self):
        """Testa exportação de relatório em JSON."""
        report = self.reporter.generate_comprehensive_report()

        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            output_file = f.name

        try:
            self.reporter.export_report(report, output_file, format='json')
            self.assertTrue(os.path.exists(output_file))

            # Verifica se é JSON válido
            import json
            with open(output_file) as f:
                loaded = json.load(f)
                self.assertIn('metadata', loaded)

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_export_html_report(self):
        """Testa exportação de relatório em HTML."""
        report = self.reporter.generate_comprehensive_report()

        with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as f:
            output_file = f.name

        try:
            self.reporter.export_report(report, output_file, format='html')
            self.assertTrue(os.path.exists(output_file))

            # Verifica se contém HTML
            with open(output_file) as f:
                content = f.read()
                self.assertIn('<!DOCTYPE html>', content)
                self.assertIn('Security Assessment Report', content)

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)


class TestOSINTModule(unittest.TestCase):
    """Testa módulo OSINT."""

    def test_osint_module_init(self):
        """Testa inicialização do módulo OSINT."""
        osint = OSINTModule()

        self.assertIsNotNone(osint.results)
        self.assertIn('target', osint.results)
        self.assertIn('domain_info', osint.results)
        self.assertIn('email_addresses', osint.results)
        self.assertIn('subdomains', osint.results)

    def test_detect_target_type(self):
        """Testa detecção de tipo de alvo."""
        osint = OSINTModule()

        self.assertEqual(osint._detect_target_type('example.com'), 'domain')
        self.assertEqual(osint._detect_target_type('user@example.com'), 'email')
        self.assertEqual(osint._detect_target_type('John Doe'), 'person')

    def test_email_validation(self):
        """Testa validação de email."""
        osint = OSINTModule()

        # Email válido
        valid = osint._validate_email('user@example.com')
        self.assertTrue(valid['format_valid'])

        # Email inválido
        invalid = osint._validate_email('not-an-email')
        self.assertFalse(invalid['format_valid'])

    def test_dns_enumeration(self):
        """Testa enumeração DNS."""
        osint = OSINTModule()

        # Usa domínio público confiável
        dns_records = osint._dns_enumeration('google.com')

        self.assertIsInstance(dns_records, dict)
        # Deve ter ao menos alguns tipos de records
        self.assertIn('A', dns_records)
        self.assertIn('NS', dns_records)


class TestIntegration(unittest.TestCase):
    """Testes de integração entre componentes."""

    def setUp(self):
        """Configura ambiente de teste."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db = DiscoveryDatabase(self.temp_db.name)
        self.reporter = AdvancedReporter(self.temp_db.name)
        self.plugin_manager = PluginManager()
        self.plugin_manager.discover_plugins()

    def tearDown(self):
        """Limpa recursos."""
        self.db.close()
        self.reporter.close()
        os.unlink(self.temp_db.name)

    def test_plugin_to_database_to_report_flow(self):
        """Testa fluxo completo: plugin -> database -> report."""
        # 1. Adiciona dados ao banco (simulando output de plugins)
        url_id = self.db.add_url('https://test.com/api', 'test.com',
                                discovered_by='katana_crawler')

        secret_id = self.db.add_secret('AKIA1234567890', 'aws_access_key',
                                       service='aws', risk_level='critical',
                                       discovered_by='secret_scanner')

        vuln_id = self.db.add_vulnerability('xss', 'high',
                                           description='Reflected XSS',
                                           discovered_by='dalfox_xss')

        # 2. Verifica se dados foram salvos
        self.assertGreater(url_id, 0)
        self.assertGreater(secret_id, 0)
        self.assertGreater(vuln_id, 0)

        # 3. Gera relatório
        report = self.reporter.generate_comprehensive_report()

        # 4. Verifica se dados aparecem no relatório
        self.assertEqual(report['executive_summary']['total_urls'], 1)
        self.assertEqual(report['executive_summary']['total_secrets'], 1)
        self.assertEqual(report['api_keys_and_secrets']['total_count'], 1)

    def test_all_plugin_categories_registered(self):
        """Verifica se todos os plugins estão em categorias corretas."""
        all_plugins = self.plugin_manager.plugins

        # Conta plugins por categoria
        recon_count = len(self.plugin_manager.get_plugins_by_category('recon'))
        vuln_count = len(self.plugin_manager.get_plugins_by_category('vuln_scan'))

        # Deve ter múltiplos plugins em cada categoria
        self.assertGreater(recon_count, 5)
        self.assertGreater(vuln_count, 5)


def run_tests():
    """Executa todos os testes."""
    # Cria test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Adiciona testes
    suite.addTests(loader.loadTestsFromTestCase(TestNewPlugins))
    suite.addTests(loader.loadTestsFromTestCase(TestDiscoveryDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestAdvancedReporter))
    suite.addTests(loader.loadTestsFromTestCase(TestOSINTModule))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Executa testes
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Resumo
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("="*60)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
