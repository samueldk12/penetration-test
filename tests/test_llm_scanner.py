"""
Testes para o módulo LLM Scanner
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest_suite.modules.llm_scanner import LLMScanner


class TestLLMScanner(unittest.TestCase):
    """Testes para LLMScanner"""

    def setUp(self):
        """Setup para cada teste"""
        self.scanner = LLMScanner(
            api_endpoint='https://api.example.com/chat',
            api_key='test_key_123',
            timeout=10
        )

    def test_initialization(self):
        """Testa inicialização"""
        self.assertEqual(self.scanner.api_endpoint, 'https://api.example.com/chat')
        self.assertEqual(self.scanner.api_key, 'test_key_123')
        self.assertEqual(self.scanner.timeout, 10)
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

    def test_session_headers(self):
        """Testa headers da sessão"""
        self.assertIn('Authorization', self.scanner.session.headers)
        self.assertEqual(
            self.scanner.session.headers['Authorization'],
            'Bearer test_key_123'
        )

    def test_extract_response_openai_format(self):
        """Testa extração de resposta formato OpenAI"""
        response_data = {
            'choices': [
                {
                    'message': {
                        'content': 'Test response'
                    }
                }
            ]
        }

        text = self.scanner._extract_response_text(response_data)
        self.assertEqual(text, 'Test response')

    def test_extract_response_anthropic_format(self):
        """Testa extração de resposta formato Anthropic"""
        response_data = {
            'completion': 'Anthropic response'
        }

        text = self.scanner._extract_response_text(response_data)
        self.assertEqual(text, 'Anthropic response')

    def test_extract_response_generic_format(self):
        """Testa extração de resposta formato genérico"""
        response_data = {
            'response': 'Generic response'
        }

        text = self.scanner._extract_response_text(response_data)
        self.assertEqual(text, 'Generic response')

    def test_add_vulnerability(self):
        """Testa adicionar vulnerabilidade"""
        self.scanner._add_vulnerability(
            'Prompt Injection',
            'CRITICAL',
            'https://api.example.com',
            'Test vulnerability',
            {'payload': 'test'}
        )

        self.assertEqual(len(self.scanner.vulnerabilities), 1)
        vuln = self.scanner.vulnerabilities[0]

        self.assertEqual(vuln['type'], 'Prompt Injection')
        self.assertEqual(vuln['severity'], 'CRITICAL')

    def test_get_report(self):
        """Testa geração de relatório"""
        # Adiciona algumas vulnerabilidades de teste
        self.scanner._add_vulnerability(
            'Test1', 'CRITICAL', 'url1', 'desc1', {}
        )
        self.scanner._add_vulnerability(
            'Test2', 'HIGH', 'url2', 'desc2', {}
        )

        report = self.scanner.get_report()

        self.assertEqual(report['total_vulnerabilities'], 2)
        self.assertEqual(report['by_severity']['CRITICAL'], 1)
        self.assertEqual(report['by_severity']['HIGH'], 1)

    @patch('requests.Session.post')
    def test_send_prompt_success(self, mock_post):
        """Testa envio de prompt bem-sucedido"""
        # Mock da resposta
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Response'}}]
        }
        mock_post.return_value = mock_response

        response = self.scanner._send_prompt('Test prompt')

        self.assertIsNotNone(response)
        mock_post.assert_called()

    @patch('requests.Session.post')
    def test_send_prompt_failure(self, mock_post):
        """Testa envio de prompt com falha"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        response = self.scanner._send_prompt('Test prompt')

        # Deve tentar múltiplos formatos
        self.assertIsNone(response)

    def test_scan_with_test_selector(self):
        """Testa scan com seletor de testes"""
        from pentest_suite.file_loader import TestSelector

        selector = TestSelector(['prompt_injection'])
        scanner = LLMScanner(
            api_endpoint='https://api.example.com',
            test_selector=selector
        )

        # Verifica que apenas o teste selecionado será executado
        self.assertTrue(selector.should_run('prompt_injection'))
        self.assertFalse(selector.should_run('jailbreak'))


if __name__ == '__main__':
    unittest.main()
