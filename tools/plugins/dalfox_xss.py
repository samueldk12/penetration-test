#!/usr/bin/env python3
"""
Dalfox XSS Scanner Plugin
Wrapper para ferramenta Dalfox - XSS scanner avançado
"""

import subprocess
import json
from typing import Dict, List, Optional
from pathlib import Path
import tempfile

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class DalfoxPlugin(PluginInterface):
    """Plugin para executar XSS scanning com Dalfox."""

    name = "dalfox_xss"
    version = "1.0.0"
    category = "vuln_scan"
    description = "Advanced XSS scanner usando Dalfox"

    def __init__(self):
        super().__init__()
        self.dalfox_path = self._find_dalfox()

    def _find_dalfox(self) -> Optional[str]:
        """Encontra o executável do Dalfox no sistema."""
        try:
            result = subprocess.run(['which', 'dalfox'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        common_paths = [
            '/usr/bin/dalfox',
            '/usr/local/bin/dalfox',
            '/go/bin/dalfox',
            str(Path.home() / 'go/bin/dalfox')
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa XSS scanning com Dalfox.

        Args:
            target: URL do alvo (com parâmetros)
            **kwargs: Opções adicionais
                - method: Método HTTP (GET, POST)
                - data: POST data
                - headers: Headers customizados
                - blind: Habilita blind XSS
                - mining_dom: Mining DOM XSS
                - timeout: Timeout do scan (default: 300)

        Returns:
            Dict com resultados do scan
        """
        if not self.dalfox_path:
            return {
                'success': False,
                'error': 'Dalfox not installed',
                'message': 'Install from: https://github.com/hahwul/dalfox'
            }

        method = kwargs.get('method', 'GET')
        data = kwargs.get('data', '')
        headers = kwargs.get('headers', {})
        blind = kwargs.get('blind', False)
        mining_dom = kwargs.get('mining_dom', True)
        timeout = kwargs.get('timeout', 300)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            cmd = [
                self.dalfox_path,
                'url', target,
                '--format', 'json',
                '--output', output_file,
                '--silence'
            ]

            if method == 'POST':
                cmd.extend(['--method', 'POST'])
                if data:
                    cmd.extend(['--data', data])

            if headers:
                for key, value in headers.items():
                    cmd.extend(['--header', f'{key}: {value}'])

            if blind:
                cmd.append('--blind')

            if mining_dom:
                cmd.append('--mining-dom')

            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            vulnerabilities = self._parse_dalfox_output(output_file)

            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerable': len(vulnerabilities) > 0,
                'xss_types': self._categorize_xss(vulnerabilities)
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Scan timeout',
                'target': target
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'target': target
            }
        finally:
            try:
                Path(output_file).unlink()
            except:
                pass

    def _parse_dalfox_output(self, json_file: str) -> List[Dict]:
        """Parse do output JSON do Dalfox."""
        vulnerabilities = []

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            if isinstance(data, list):
                for vuln in data:
                    vulnerabilities.append({
                        'type': vuln.get('type', 'xss'),
                        'param': vuln.get('param', ''),
                        'payload': vuln.get('payload', ''),
                        'evidence': vuln.get('evidence', ''),
                        'method': vuln.get('method', 'GET'),
                        'data': vuln.get('data', ''),
                        'poc': vuln.get('poc', ''),
                        'severity': self._determine_xss_severity(vuln)
                    })

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error parsing Dalfox output: {e}")

        return vulnerabilities

    def _determine_xss_severity(self, vuln: Dict) -> str:
        """Determina severidade do XSS."""
        xss_type = vuln.get('type', '').lower()

        if 'stored' in xss_type or 'persistent' in xss_type:
            return 'critical'
        elif 'dom' in xss_type:
            return 'high'
        elif 'reflected' in xss_type:
            return 'medium'

        return 'medium'

    def _categorize_xss(self, vulnerabilities: List[Dict]) -> Dict:
        """Categoriza tipos de XSS encontrados."""
        categories = {
            'reflected': 0,
            'stored': 0,
            'dom': 0,
            'blind': 0,
            'other': 0
        }

        for vuln in vulnerabilities:
            xss_type = vuln.get('type', '').lower()

            if 'reflected' in xss_type:
                categories['reflected'] += 1
            elif 'stored' in xss_type or 'persistent' in xss_type:
                categories['stored'] += 1
            elif 'dom' in xss_type:
                categories['dom'] += 1
            elif 'blind' in xss_type:
                categories['blind'] += 1
            else:
                categories['other'] += 1

        return categories


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dalfox_xss.py <target_url>")
        print("Example: python dalfox_xss.py 'https://example.com/search?q=test'")
        sys.exit(1)

    plugin = DalfoxPlugin()
    target = sys.argv[1]

    print(f"Running Dalfox XSS scan on {target}...")
    result = plugin.run(target)

    print(json.dumps(result, indent=2))
