"""
Testes para o módulo file_loader
"""

import unittest
import tempfile
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest_suite.file_loader import (
    FileLoader, PayloadManager, TargetManager, TestSelector
)


class TestFileLoader(unittest.TestCase):
    """Testes para FileLoader"""

    def setUp(self):
        """Setup para cada teste"""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)

    def tearDown(self):
        """Cleanup após cada teste"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_load_urls(self):
        """Testa carregamento de URLs"""
        urls = [
            'https://example.com',
            'https://test.com',
            '# comment',
            '',
            'https://site.com'
        ]

        with open(self.temp_file.name, 'w') as f:
            for url in urls:
                f.write(url + '\n')

        loaded_urls = FileLoader.load_urls(self.temp_file.name)

        # Deve carregar apenas 3 URLs (ignora comentários e linhas vazias)
        self.assertEqual(len(loaded_urls), 3)
        self.assertIn('https://example.com', loaded_urls)
        self.assertNotIn('# comment', loaded_urls)

    def test_load_payloads(self):
        """Testa carregamento de payloads"""
        payloads = [
            "' OR '1'='1",
            '<script>alert(1)</script>',
            '# comment',
            "' UNION SELECT NULL--"
        ]

        with open(self.temp_file.name, 'w') as f:
            for payload in payloads:
                f.write(payload + '\n')

        loaded_payloads = FileLoader.load_payloads(self.temp_file.name)

        self.assertEqual(len(loaded_payloads), 3)

    def test_load_json_config(self):
        """Testa carregamento de config JSON"""
        config = {
            'timeout': 30,
            'verify_ssl': False
        }

        with open(self.temp_file.name, 'w') as f:
            json.dump(config, f)

        loaded_config = FileLoader.load_json_config(self.temp_file.name)

        self.assertEqual(loaded_config['timeout'], 30)
        self.assertFalse(loaded_config['verify_ssl'])

    def test_load_target_list(self):
        """Testa carregamento de lista de targets"""
        targets = [
            {'url': 'https://example.com', 'priority': 'high'},
            {'url': 'https://test.com', 'priority': 'low'}
        ]

        with open(self.temp_file.name, 'w') as f:
            json.dump(targets, f)

        loaded_targets = FileLoader.load_target_list(self.temp_file.name)

        self.assertEqual(len(loaded_targets), 2)
        self.assertEqual(loaded_targets[0]['priority'], 'high')


class TestPayloadManager(unittest.TestCase):
    """Testes para PayloadManager"""

    def test_initialization(self):
        """Testa inicialização"""
        manager = PayloadManager()

        self.assertIn('sqli', manager.payloads)
        self.assertIn('xss', manager.payloads)
        self.assertEqual(len(manager.get_payloads('sqli')), 0)

    def test_add_payload(self):
        """Testa adicionar payload"""
        manager = PayloadManager()
        manager.add_payload('sqli', "' OR '1'='1")

        payloads = manager.get_payloads('sqli')
        self.assertEqual(len(payloads), 1)
        self.assertIn("' OR '1'='1", payloads)

    def test_get_all_categories(self):
        """Testa obter todas as categorias"""
        manager = PayloadManager()
        categories = manager.get_all_categories()

        self.assertIn('sqli', categories)
        self.assertIn('xss', categories)
        self.assertIn('prompt_injection', categories)


class TestTargetManager(unittest.TestCase):
    """Testes para TargetManager"""

    def test_initialization(self):
        """Testa inicialização"""
        manager = TargetManager()
        self.assertEqual(len(manager.targets), 0)

    def test_add_target(self):
        """Testa adicionar target"""
        manager = TargetManager()
        manager.add_target('https://example.com', priority='high')

        self.assertEqual(len(manager.targets), 1)
        self.assertEqual(manager.targets[0]['url'], 'https://example.com')
        self.assertEqual(manager.targets[0]['priority'], 'high')

    def test_get_urls(self):
        """Testa obter apenas URLs"""
        manager = TargetManager()
        manager.add_target('https://example.com')
        manager.add_target('https://test.com')

        urls = manager.get_urls()
        self.assertEqual(len(urls), 2)
        self.assertIn('https://example.com', urls)

    def test_filter_targets(self):
        """Testa filtrar targets"""
        manager = TargetManager()
        manager.add_target('https://example.com', priority='high')
        manager.add_target('https://test.com', priority='low')

        high_priority = manager.get_targets(filter_by={'priority': 'high'})
        self.assertEqual(len(high_priority), 1)
        self.assertEqual(high_priority[0]['priority'], 'high')


class TestTestSelector(unittest.TestCase):
    """Testes para TestSelector"""

    def test_initialization(self):
        """Testa inicialização"""
        selector = TestSelector()
        self.assertEqual(len(selector.selected_tests), 0)

    def test_add_test(self):
        """Testa adicionar teste"""
        selector = TestSelector()
        selector.add_test('sqli')

        self.assertIn('sqli', selector.selected_tests)

    def test_should_run_all(self):
        """Testa execução de todos quando nenhum selecionado"""
        selector = TestSelector()

        # Se nenhum teste selecionado, executa todos
        self.assertTrue(selector.should_run('sqli'))
        self.assertTrue(selector.should_run('xss'))

    def test_should_run_selective(self):
        """Testa execução seletiva"""
        selector = TestSelector(['sqli', 'xss'])

        self.assertTrue(selector.should_run('sqli'))
        self.assertTrue(selector.should_run('xss'))
        self.assertFalse(selector.should_run('csrf'))

    def test_get_selected_tests(self):
        """Testa obter testes selecionados"""
        selector = TestSelector(['sqli', 'xss'])
        tests = selector.get_selected_tests()

        self.assertEqual(len(tests), 2)
        self.assertIn('sqli', tests)


if __name__ == '__main__':
    unittest.main()
