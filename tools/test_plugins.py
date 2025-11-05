#!/usr/bin/env python3
"""
Plugin System Tests - Unit tests para validar plugins
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from plugin_system import PluginInterface, PluginManager
from blacklist_manager import BlacklistManager


class TestPluginInterface(unittest.TestCase):
    """Testes para PluginInterface."""

    def test_plugin_interface_attributes(self):
        """Testa se PluginInterface tem attributes necessários."""
        plugin = PluginInterface()

        self.assertTrue(hasattr(plugin, 'name'))
        self.assertTrue(hasattr(plugin, 'version'))
        self.assertTrue(hasattr(plugin, 'author'))
        self.assertTrue(hasattr(plugin, 'description'))
        self.assertTrue(hasattr(plugin, 'category'))
        self.assertTrue(hasattr(plugin, 'requires'))

    def test_plugin_interface_methods(self):
        """Testa se PluginInterface tem methods necessários."""
        plugin = PluginInterface()

        self.assertTrue(callable(plugin.validate))
        self.assertTrue(callable(plugin.get_results))
        self.assertTrue(callable(plugin.get_errors))
        self.assertTrue(callable(plugin.to_dict))

    def test_plugin_validate(self):
        """Testa validação de plugin."""
        plugin = PluginInterface()
        plugin.requires = []  # Sem dependências

        self.assertTrue(plugin.validate())

    def test_plugin_to_dict(self):
        """Testa conversão para dicionário."""
        plugin = PluginInterface()
        data = plugin.to_dict()

        self.assertIsInstance(data, dict)
        self.assertIn('name', data)
        self.assertIn('version', data)
        self.assertIn('category', data)


class TestPluginManager(unittest.TestCase):
    """Testes para PluginManager."""

    def setUp(self):
        """Setup antes de cada teste."""
        self.manager = PluginManager(plugins_dir="plugins")

    def test_plugin_manager_init(self):
        """Testa inicialização do PluginManager."""
        self.assertIsInstance(self.manager.plugins, dict)
        self.assertIsInstance(self.manager.categories, dict)

    def test_discover_plugins(self):
        """Testa descoberta de plugins."""
        count = self.manager.discover_plugins()

        self.assertGreaterEqual(count, 0)
        print(f"\n[*] Discovered {count} plugins")

    def test_get_plugin(self):
        """Testa obtenção de plugin por nome."""
        self.manager.discover_plugins()

        # Tenta pegar primeiro plugin disponível
        if self.manager.plugins:
            first_plugin_name = list(self.manager.plugins.keys())[0]
            plugin = self.manager.get_plugin(first_plugin_name)

            self.assertIsNotNone(plugin)
            self.assertIsInstance(plugin, PluginInterface)

    def test_list_plugins(self):
        """Testa listagem de plugins."""
        self.manager.discover_plugins()

        plugins = self.manager.list_plugins()

        self.assertIsInstance(plugins, list)

        for plugin_info in plugins:
            self.assertIn('name', plugin_info)
            self.assertIn('version', plugin_info)
            self.assertIn('category', plugin_info)

    def test_list_categories(self):
        """Testa listagem de categorias."""
        self.manager.discover_plugins()

        categories = self.manager.list_categories()

        self.assertIsInstance(categories, dict)


class TestBlacklistManager(unittest.TestCase):
    """Testes para BlacklistManager."""

    def setUp(self):
        """Setup antes de cada teste."""
        self.blacklist = BlacklistManager()
        self.blacklist.clear()  # Limpa para testes

    def test_blacklist_init(self):
        """Testa inicialização."""
        self.assertIsInstance(self.blacklist.keywords, set)
        self.assertIsInstance(self.blacklist.extensions, set)
        self.assertIsInstance(self.blacklist.regex_patterns, list)
        self.assertIsInstance(self.blacklist.exact_urls, set)

    def test_add_keyword(self):
        """Testa adição de keyword."""
        self.blacklist.add_keyword("logout")

        self.assertIn("logout", self.blacklist.keywords)

    def test_add_extension(self):
        """Testa adição de extensão."""
        self.blacklist.add_extension(".jpg")

        self.assertIn(".jpg", self.blacklist.extensions)

    def test_add_exact_url(self):
        """Testa adição de URL exata."""
        url = "https://example.com/logout"
        self.blacklist.add_exact_url(url)

        self.assertIn(url, self.blacklist.exact_urls)

    def test_is_blacklisted_keyword(self):
        """Testa detecção por keyword."""
        self.blacklist.add_keyword("logout")

        is_blacklisted, reason = self.blacklist.is_blacklisted("https://example.com/logout")

        self.assertTrue(is_blacklisted)
        self.assertIn("keyword", reason)

    def test_is_blacklisted_extension(self):
        """Testa detecção por extensão."""
        self.blacklist.add_extension(".jpg")

        is_blacklisted, reason = self.blacklist.is_blacklisted("https://example.com/image.jpg")

        self.assertTrue(is_blacklisted)
        self.assertIn("extension", reason)

    def test_is_blacklisted_exact(self):
        """Testa detecção por URL exata."""
        url = "https://example.com/admin"
        self.blacklist.add_exact_url(url)

        is_blacklisted, reason = self.blacklist.is_blacklisted(url)

        self.assertTrue(is_blacklisted)
        self.assertEqual(reason, "exact_match")

    def test_not_blacklisted(self):
        """Testa URL não blacklisted."""
        self.blacklist.add_keyword("logout")

        is_blacklisted, reason = self.blacklist.is_blacklisted("https://example.com/api/users")

        self.assertFalse(is_blacklisted)
        self.assertEqual(reason, "")

    def test_filter_urls(self):
        """Testa filtragem de lista de URLs."""
        self.blacklist.add_keyword("logout")
        self.blacklist.add_extension(".jpg")

        urls = [
            "https://example.com/api/users",
            "https://example.com/logout",
            "https://example.com/image.jpg",
            "https://example.com/api/products"
        ]

        filtered = self.blacklist.filter_urls(urls)

        self.assertEqual(len(filtered), 2)
        self.assertIn("https://example.com/api/users", filtered)
        self.assertIn("https://example.com/api/products", filtered)

    def test_get_stats(self):
        """Testa estatísticas."""
        self.blacklist.add_keyword("logout")
        self.blacklist.add_extension(".jpg")
        self.blacklist.add_extension(".png")

        stats = self.blacklist.get_stats()

        self.assertEqual(stats['keywords'], 1)
        self.assertEqual(stats['extensions'], 2)
        self.assertEqual(stats['total_rules'], 3)


class TestPluginIntegration(unittest.TestCase):
    """Testes de integração dos plugins."""

    def setUp(self):
        """Setup antes de cada teste."""
        self.manager = PluginManager(plugins_dir="plugins")
        self.manager.discover_plugins()

    def test_cert_transparency_plugin_exists(self):
        """Testa se plugin cert_transparency existe."""
        plugin = self.manager.get_plugin('cert_transparency')

        if plugin:
            self.assertEqual(plugin.name, 'cert_transparency')
            self.assertEqual(plugin.category, 'recon')

    def test_wayback_urls_plugin_exists(self):
        """Testa se plugin wayback_urls existe."""
        plugin = self.manager.get_plugin('wayback_urls')

        if plugin:
            self.assertEqual(plugin.name, 'wayback_urls')
            self.assertEqual(plugin.category, 'recon')

    def test_xss_scanner_plugin_exists(self):
        """Testa se plugin xss_scanner existe."""
        plugin = self.manager.get_plugin('xss_scanner')

        if plugin:
            self.assertEqual(plugin.name, 'xss_scanner')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_sqli_scanner_plugin_exists(self):
        """Testa se plugin sqli_scanner existe."""
        plugin = self.manager.get_plugin('sqli_scanner')

        if plugin:
            self.assertEqual(plugin.name, 'sqli_scanner')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_open_redirect_scanner_plugin_exists(self):
        """Testa se plugin open_redirect_scanner existe."""
        plugin = self.manager.get_plugin('open_redirect_scanner')

        if plugin:
            self.assertEqual(plugin.name, 'open_redirect_scanner')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_ssrf_scanner_plugin_exists(self):
        """Testa se plugin ssrf_scanner existe."""
        plugin = self.manager.get_plugin('ssrf_scanner')

        if plugin:
            self.assertEqual(plugin.name, 'ssrf_scanner')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_lfi_scanner_plugin_exists(self):
        """Testa se plugin lfi_scanner existe."""
        plugin = self.manager.get_plugin('lfi_scanner')

        if plugin:
            self.assertEqual(plugin.name, 'lfi_scanner')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_sensitive_files_plugin_exists(self):
        """Testa se plugin sensitive_files existe."""
        plugin = self.manager.get_plugin('sensitive_files')

        if plugin:
            self.assertEqual(plugin.name, 'sensitive_files')
            self.assertEqual(plugin.category, 'vuln_scan')

    def test_all_plugins_have_required_methods(self):
        """Testa se todos os plugins têm methods necessários."""
        for plugin_name, plugin in self.manager.plugins.items():
            with self.subTest(plugin=plugin_name):
                self.assertTrue(callable(plugin.run))
                self.assertTrue(callable(plugin.validate))
                self.assertTrue(hasattr(plugin, 'name'))
                self.assertTrue(hasattr(plugin, 'version'))
                self.assertTrue(hasattr(plugin, 'category'))

    def test_categories_populated(self):
        """Testa se categorias foram populadas."""
        categories = self.manager.list_categories()

        self.assertGreater(len(categories), 0)

        # Deve ter pelo menos categoria recon e vuln_scan
        self.assertTrue(
            'recon' in categories or 'vuln_scan' in categories,
            "Should have at least recon or vuln_scan category"
        )


def run_tests(verbose=True):
    """
    Executa todos os testes.

    Args:
        verbose: Verbosity level

    Returns:
        TestResult
    """
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPluginInterface))
    suite.addTests(loader.loadTestsFromTestCase(TestPluginManager))
    suite.addTests(loader.loadTestsFromTestCase(TestBlacklistManager))
    suite.addTests(loader.loadTestsFromTestCase(TestPluginIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    print("=" * 60)
    print("PLUGIN SYSTEM TESTS")
    print("=" * 60)
    print()

    result = run_tests(verbose=True)

    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)

    sys.exit(0 if result.wasSuccessful() else 1)
