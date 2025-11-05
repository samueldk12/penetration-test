#!/usr/bin/env python3
"""
Nuclei Scanner Plugin
Wrapper para ferramenta Nuclei - Template-based vulnerability scanner
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


class NucleiPlugin(PluginInterface):
    """Plugin para executar scans Nuclei em alvos."""

    name = "nuclei_scanner"
    version = "1.0.0"
    category = "vuln_scan"
    description = "Template-based vulnerability scanner usando Nuclei"

    def __init__(self):
        super().__init__()
        self.nuclei_path = self._find_nuclei()

    def _find_nuclei(self) -> Optional[str]:
        """Encontra o executável do Nuclei no sistema."""
        try:
            result = subprocess.run(['which', 'nuclei'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/nuclei',
            '/usr/local/bin/nuclei',
            '/go/bin/nuclei',
            str(Path.home() / 'go/bin/nuclei')
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa scan Nuclei no alvo.

        Args:
            target: URL, IP ou arquivo com lista de alvos
            **kwargs: Opções adicionais
                - severity: Filtro de severidade (critical, high, medium, low, info)
                - templates: Lista de templates específicos
                - tags: Tags para filtrar templates
                - timeout: Timeout do scan (default: 300)
                - update_templates: Atualiza templates antes do scan

        Returns:
            Dict com resultados do scan
        """
        if not self.nuclei_path:
            return {
                'success': False,
                'error': 'Nuclei not installed',
                'message': 'Install from: https://github.com/projectdiscovery/nuclei'
            }

        timeout = kwargs.get('timeout', 300)
        severity = kwargs.get('severity', ['critical', 'high', 'medium'])
        tags = kwargs.get('tags', [])
        templates = kwargs.get('templates', [])
        update_templates = kwargs.get('update_templates', False)

        # Atualiza templates se solicitado
        if update_templates:
            self._update_templates()

        # Cria arquivo temporário para output JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            # Constrói comando Nuclei
            cmd = [
                self.nuclei_path,
                '-u', target,
                '-json',
                '-o', output_file,
                '-silent'
            ]

            # Adiciona filtros de severidade
            if severity:
                if isinstance(severity, list):
                    cmd.extend(['-severity', ','.join(severity)])
                else:
                    cmd.extend(['-severity', severity])

            # Adiciona tags
            if tags:
                if isinstance(tags, list):
                    cmd.extend(['-tags', ','.join(tags)])
                else:
                    cmd.extend(['-tags', tags])

            # Adiciona templates específicos
            if templates:
                for template in templates:
                    cmd.extend(['-t', template])

            # Executa Nuclei
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            # Parse do JSON output
            vulnerabilities = self._parse_nuclei_json(output_file)

            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulnerabilities,
                'total_findings': len(vulnerabilities),
                'severity_breakdown': self._calculate_severity(vulnerabilities),
                'unique_templates': len(set(v.get('template_id', '') for v in vulnerabilities))
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

    def _update_templates(self):
        """Atualiza templates do Nuclei."""
        try:
            subprocess.run(
                [self.nuclei_path, '-update-templates'],
                timeout=60,
                capture_output=True
            )
        except Exception:
            pass

    def _parse_nuclei_json(self, json_file: str) -> List[Dict]:
        """Parse do output JSON do Nuclei."""
        vulnerabilities = []

        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)

                        vuln = {
                            'template_id': data.get('template-id', ''),
                            'template_name': data.get('info', {}).get('name', ''),
                            'severity': data.get('info', {}).get('severity', 'info'),
                            'description': data.get('info', {}).get('description', ''),
                            'matched_at': data.get('matched-at', ''),
                            'extracted_results': data.get('extracted-results', []),
                            'matcher_name': data.get('matcher-name', ''),
                            'type': data.get('type', ''),
                            'host': data.get('host', ''),
                            'metadata': data.get('info', {}).get('metadata', {}),
                            'tags': data.get('info', {}).get('tags', []),
                            'references': data.get('info', {}).get('reference', [])
                        }

                        vulnerabilities.append(vuln)

                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error parsing Nuclei JSON: {e}")

        return vulnerabilities

    def _calculate_severity(self, vulnerabilities: List[Dict]) -> Dict:
        """Calcula breakdown de severidade."""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            breakdown[severity] = breakdown.get(severity, 0) + 1

        return breakdown


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nuclei_scanner.py <target_url> [severity]")
        print("Example: python nuclei_scanner.py https://example.com critical,high")
        sys.exit(1)

    plugin = NucleiPlugin()
    target = sys.argv[1]
    severity = sys.argv[2].split(',') if len(sys.argv) > 2 else ['critical', 'high', 'medium']

    print(f"Running Nuclei scan on {target}...")
    result = plugin.run(target, severity=severity)

    print(json.dumps(result, indent=2))
