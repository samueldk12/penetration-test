"""
Testes para o módulo de configuração
"""

import unittest
import sys
import os

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest_suite.config import ScanConfig, ProxyManager, AuthManager


class TestScanConfig(unittest.TestCase):
    """Testes para ScanConfig"""

    def test_default_config(self):
        """Testa configuração padrão"""
        config = ScanConfig()

        self.assertIsNone(config.proxies)
        self.assertFalse(config.verify_ssl)
        self.assertEqual(config.timeout, 10)
        self.assertEqual(config.max_retries, 3)

    def test_custom_config(self):
        """Testa configuração customizada"""
        config = ScanConfig(
            timeout=30,
            max_retries=5,
            user_agent='Custom UA'
        )

        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.user_agent, 'Custom UA')

    def test_session_creation(self):
        """Testa criação de sessão"""
        config = ScanConfig(user_agent='Test UA')
        session = config.get_session()

        self.assertIn('User-Agent', session.headers)
        self.assertEqual(session.headers['User-Agent'], 'Test UA')

    def test_basic_auth(self):
        """Testa autenticação básica"""
        config = ScanConfig(
            auth_type='basic',
            username='admin',
            password='secret'
        )
        session = config.get_session()

        self.assertIsNotNone(session.auth)

    def test_bearer_auth(self):
        """Testa Bearer token"""
        config = ScanConfig(
            auth_type='bearer',
            bearer_token='test_token_123'
        )
        session = config.get_session()

        self.assertIn('Authorization', session.headers)
        self.assertEqual(session.headers['Authorization'], 'Bearer test_token_123')

    def test_to_dict(self):
        """Testa conversão para dicionário"""
        config = ScanConfig(timeout=20)
        config_dict = config.to_dict()

        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict['timeout'], 20)

    def test_from_dict(self):
        """Testa criação a partir de dicionário"""
        config_dict = {'timeout': 25, 'max_retries': 4}
        config = ScanConfig.from_dict(config_dict)

        self.assertEqual(config.timeout, 25)
        self.assertEqual(config.max_retries, 4)


class TestProxyManager(unittest.TestCase):
    """Testes para ProxyManager"""

    def test_initialization(self):
        """Testa inicialização"""
        manager = ProxyManager()
        self.assertEqual(len(manager.proxies), 0)

    def test_add_proxy(self):
        """Testa adicionar proxy"""
        manager = ProxyManager()
        manager.add_proxy('http://proxy:8080')

        self.assertEqual(len(manager.proxies), 1)
        self.assertIn('http', manager.proxies[0])

    def test_parse_http_proxy(self):
        """Testa parse de proxy HTTP"""
        manager = ProxyManager()
        proxy = manager._parse_proxy('http://proxy.example.com:8080')

        self.assertIsNotNone(proxy)
        self.assertIn('http', proxy)
        self.assertIn('https', proxy)

    def test_parse_socks_proxy(self):
        """Testa parse de proxy SOCKS"""
        manager = ProxyManager()
        proxy = manager._parse_proxy('socks5://127.0.0.1:9050')

        self.assertIsNotNone(proxy)
        self.assertTrue(proxy['http'].startswith('socks5://'))


class TestAuthManager(unittest.TestCase):
    """Testes para AuthManager"""

    def test_basic_auth_creation(self):
        """Testa criação de Basic Auth"""
        auth = AuthManager.create_basic_auth('user', 'pass')
        self.assertIsNotNone(auth)

    def test_bearer_header(self):
        """Testa criação de Bearer header"""
        header = AuthManager.create_bearer_header('token123')

        self.assertIn('Authorization', header)
        self.assertEqual(header['Authorization'], 'Bearer token123')

    def test_api_key_header(self):
        """Testa criação de API Key header"""
        header = AuthManager.create_api_key_header('key123', 'X-API-Key')

        self.assertIn('X-API-Key', header)
        self.assertEqual(header['X-API-Key'], 'key123')


if __name__ == '__main__':
    unittest.main()
