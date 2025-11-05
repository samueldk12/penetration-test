#!/usr/bin/env python3
"""
Katana Crawler Plugin
Wrapper para ferramenta Katana - Web crawler
"""

import subprocess
import json
from typing import Dict, List, Optional
from pathlib import Path
import tempfile

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class KatanaPlugin(PluginInterface):
    """Plugin para executar web crawling com Katana."""

    name = "katana_crawler"
    version = "1.0.0"
    category = "recon"
    description = "Web crawler usando Katana"

    def __init__(self):
        super().__init__()
        self.katana_path = self._find_katana()

    def _find_katana(self) -> Optional[str]:
        """Encontra o executável do Katana no sistema."""
        try:
            result = subprocess.run(['which', 'katana'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        common_paths = [
            '/usr/bin/katana',
            '/usr/local/bin/katana',
            '/go/bin/katana',
            str(Path.home() / 'go/bin/katana')
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa crawling com Katana.

        Args:
            target: URL do alvo
            **kwargs: Opções adicionais
                - depth: Profundidade do crawl (default: 3)
                - js_crawl: Habilita parsing de JS (default: True)
                - headless: Usa headless browser (default: False)
                - timeout: Timeout do scan (default: 300)
                - scope: Escopo (in-scope, out-of-scope)
                - fields: Campos para extrair (url, path, query, etc)

        Returns:
            Dict com resultados do crawling
        """
        if not self.katana_path:
            return {
                'success': False,
                'error': 'Katana not installed',
                'message': 'Install from: https://github.com/projectdiscovery/katana'
            }

        depth = kwargs.get('depth', 3)
        js_crawl = kwargs.get('js_crawl', True)
        headless = kwargs.get('headless', False)
        timeout = kwargs.get('timeout', 300)
        scope = kwargs.get('scope', 'in-scope')

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            cmd = [
                self.katana_path,
                '-u', target,
                '-d', str(depth),
                '-jsonl',
                '-o', output_file,
                '-silent'
            ]

            if js_crawl:
                cmd.append('-jc')

            if headless:
                cmd.append('-headless')

            if scope:
                cmd.extend(['-scope', scope])

            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            urls = self._parse_katana_output(output_file)

            return {
                'success': True,
                'target': target,
                'urls': urls,
                'total_urls': len(urls),
                'depth': depth,
                'url_types': self._categorize_urls(urls)
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Crawling timeout',
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

    def _parse_katana_output(self, json_file: str) -> List[Dict]:
        """Parse do output JSONL do Katana."""
        urls = []

        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        urls.append({
                            'url': data.get('request', {}).get('endpoint', ''),
                            'method': data.get('request', {}).get('method', 'GET'),
                            'source': data.get('request', {}).get('source', ''),
                            'status_code': data.get('response', {}).get('status_code', 0),
                            'content_type': data.get('response', {}).get('headers', {}).get('content-type', [''])[0] if data.get('response', {}).get('headers', {}).get('content-type') else ''
                        })
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error parsing Katana output: {e}")

        return urls

    def _categorize_urls(self, urls: List[Dict]) -> Dict:
        """Categoriza URLs por tipo."""
        categories = {
            'api': 0,
            'static': 0,
            'dynamic': 0,
            'admin': 0,
            'other': 0
        }

        for url_data in urls:
            url = url_data.get('url', '').lower()

            if '/api/' in url or url.endswith('.json'):
                categories['api'] += 1
            elif any(ext in url for ext in ['.js', '.css', '.jpg', '.png', '.gif', '.svg']):
                categories['static'] += 1
            elif any(word in url for word in ['admin', 'dashboard', 'panel']):
                categories['admin'] += 1
            elif '?' in url:
                categories['dynamic'] += 1
            else:
                categories['other'] += 1

        return categories


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python katana_crawler.py <target_url>")
        sys.exit(1)

    plugin = KatanaPlugin()
    target = sys.argv[1]

    print(f"Running Katana crawl on {target}...")
    result = plugin.run(target)

    print(json.dumps(result, indent=2))
