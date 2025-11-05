#!/usr/bin/env python3
"""
Nikto Web Scanner Plugin
Wrapper para ferramenta Nikto - Web server scanner
"""

import subprocess
import json
import re
from typing import Dict, List, Optional
from pathlib import Path
import tempfile

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class NiktoPlugin(PluginInterface):
    """Plugin para executar scans Nikto em alvos web."""

    name = "nikto_scanner"
    version = "1.0.0"
    category = "vuln_scan"
    description = "Web server vulnerability scanner usando Nikto"

    def __init__(self):
        super().__init__()
        self.nikto_path = self._find_nikto()

    def _find_nikto(self) -> Optional[str]:
        """Encontra o executável do Nikto no sistema."""
        try:
            result = subprocess.run(['which', 'nikto'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/program/nikto.pl'
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa scan Nikto no alvo.

        Args:
            target: URL ou IP do alvo
            **kwargs: Opções adicionais
                - timeout: Timeout do scan (default: 600)
                - tuning: Tipo de scan (1-9)
                - ssl: Força SSL/TLS

        Returns:
            Dict com resultados do scan
        """
        if not self.nikto_path:
            return {
                'success': False,
                'error': 'Nikto not installed',
                'message': 'Install with: apt-get install nikto'
            }

        timeout = kwargs.get('timeout', 600)
        tuning = kwargs.get('tuning', '1234567')
        force_ssl = kwargs.get('ssl', False)

        # Cria arquivo temporário para output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
            output_file = tmp.name

        try:
            # Constrói comando Nikto
            cmd = [
                self.nikto_path,
                '-h', target,
                '-Tuning', tuning,
                '-Format', 'xml',
                '-output', output_file
            ]

            if force_ssl:
                cmd.extend(['-ssl'])

            # Executa Nikto
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            # Parse do XML output
            vulnerabilities = self._parse_nikto_xml(output_file)

            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulnerabilities,
                'total_findings': len(vulnerabilities),
                'severity_breakdown': self._calculate_severity(vulnerabilities)
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
            # Limpa arquivo temporário
            try:
                Path(output_file).unlink()
            except:
                pass

    def _parse_nikto_xml(self, xml_file: str) -> List[Dict]:
        """Parse do output XML do Nikto."""
        vulnerabilities = []

        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for item in root.findall('.//item'):
                vuln = {
                    'id': item.get('id', ''),
                    'osvdb_id': item.get('osvdb', ''),
                    'method': item.get('method', 'GET'),
                    'url': item.findtext('uri', ''),
                    'description': item.findtext('description', ''),
                    'severity': self._determine_severity(item),
                    'references': []
                }

                # Extrai referências
                refs = item.findtext('namelink', '')
                if refs:
                    vuln['references'].append(refs)

                vulnerabilities.append(vuln)

        except Exception as e:
            print(f"Error parsing Nikto XML: {e}")

        return vulnerabilities

    def _determine_severity(self, item) -> str:
        """Determina severidade baseado na descrição."""
        description = item.findtext('description', '').lower()

        # Padrões de alta severidade
        high_patterns = [
            'sql injection', 'command injection', 'remote code',
            'arbitrary file', 'authentication bypass', 'default credentials'
        ]

        # Padrões de média severidade
        medium_patterns = [
            'xss', 'cross-site', 'disclosure', 'information leak',
            'outdated', 'misconfiguration'
        ]

        for pattern in high_patterns:
            if pattern in description:
                return 'high'

        for pattern in medium_patterns:
            if pattern in description:
                return 'medium'

        return 'low'

    def _calculate_severity(self, vulnerabilities: List[Dict]) -> Dict:
        """Calcula breakdown de severidade."""
        breakdown = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            breakdown[severity] = breakdown.get(severity, 0) + 1

        return breakdown


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nikto_scanner.py <target_url>")
        sys.exit(1)

    plugin = NiktoPlugin()
    target = sys.argv[1]

    print(f"Running Nikto scan on {target}...")
    result = plugin.run(target)

    print(json.dumps(result, indent=2))
