#!/usr/bin/env python3
"""
JavaScript Plugin Runner
Sistema para executar plugins JavaScript via Node.js
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
import logging


class JSPluginRunner:
    """Executa plugins JavaScript via Node.js."""

    def __init__(self, plugins_dir: str = None):
        self.plugins_dir = plugins_dir or str(Path(__file__).parent / 'js_plugins')
        self.node_path = self._find_node()
        self.logger = logging.getLogger(__name__)

    def _find_node(self) -> Optional[str]:
        """Encontra executável do Node.js."""
        try:
            result = subprocess.run(['which', 'node'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/node',
            '/usr/local/bin/node',
            '/opt/node/bin/node'
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def is_available(self) -> bool:
        """Verifica se Node.js está disponível."""
        return self.node_path is not None

    def discover_js_plugins(self) -> List[Dict]:
        """Descobre plugins JavaScript disponíveis."""
        plugins = []

        if not os.path.exists(self.plugins_dir):
            self.logger.warning(f"JS plugins directory not found: {self.plugins_dir}")
            return plugins

        for file in Path(self.plugins_dir).glob('*.js'):
            plugin_info = self._get_plugin_info(file)
            if plugin_info:
                plugins.append(plugin_info)

        return plugins

    def _get_plugin_info(self, plugin_file: Path) -> Optional[Dict]:
        """Extrai informações do plugin JavaScript."""
        try:
            # Lê primeiras linhas do arquivo para extrair metadados
            with open(plugin_file, 'r') as f:
                lines = f.readlines()[:30]  # Primeiras 30 linhas

            metadata = {
                'name': plugin_file.stem,
                'file': str(plugin_file),
                'type': 'javascript',
                'description': '',
                'category': 'unknown',
                'version': '1.0.0'
            }

            # Parse de comentários de metadados
            in_comment_block = False
            for line in lines:
                line = line.strip()

                # Detecta bloco de comentários
                if line.startswith('/**'):
                    in_comment_block = True
                    continue
                elif line.startswith('*/'):
                    in_comment_block = False
                    break

                if in_comment_block or line.startswith('*'):
                    line = line.lstrip('*').strip()

                    # Parse de tags
                    if line.startswith('@name'):
                        metadata['name'] = line.split('@name')[1].strip()
                    elif line.startswith('@description'):
                        metadata['description'] = line.split('@description')[1].strip()
                    elif line.startswith('@category'):
                        metadata['category'] = line.split('@category')[1].strip()
                    elif line.startswith('@version'):
                        metadata['version'] = line.split('@version')[1].strip()
                    elif not line.startswith('@') and line:
                        # Primeira linha de descrição
                        if not metadata['description']:
                            metadata['description'] = line

            return metadata

        except Exception as e:
            self.logger.error(f"Error reading JS plugin {plugin_file}: {e}")
            return None

    def run_plugin(self, plugin_file: str, target: str, **kwargs) -> Dict:
        """
        Executa plugin JavaScript.

        Args:
            plugin_file: Path para o arquivo .js do plugin
            target: URL/domain alvo
            **kwargs: Argumentos adicionais para o plugin

        Returns:
            Dict com resultados do plugin
        """
        if not self.node_path:
            return {
                'success': False,
                'error': 'Node.js not installed',
                'message': 'Install Node.js from https://nodejs.org/'
            }

        if not os.path.exists(plugin_file):
            return {
                'success': False,
                'error': 'Plugin file not found',
                'file': plugin_file
            }

        try:
            # Prepara argumentos
            args = {
                'target': target,
                **kwargs
            }

            # Executa plugin Node.js
            cmd = [
                self.node_path,
                plugin_file,
                json.dumps(args)
            ]

            timeout = kwargs.get('timeout', 300)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse output JSON
            if result.returncode == 0:
                try:
                    output = json.loads(result.stdout)
                    return {
                        'success': True,
                        'plugin': plugin_file,
                        'results': output
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'plugin': plugin_file,
                        'raw_output': result.stdout,
                        'note': 'Plugin did not return JSON'
                    }
            else:
                return {
                    'success': False,
                    'plugin': plugin_file,
                    'error': result.stderr,
                    'exit_code': result.returncode
                }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Plugin execution timeout',
                'timeout': timeout
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def list_plugins(self) -> List[str]:
        """Lista todos os plugins JavaScript disponíveis."""
        plugins = self.discover_js_plugins()
        return [p['name'] for p in plugins]


if __name__ == "__main__":
    import sys

    runner = JSPluginRunner()

    if not runner.is_available():
        print("Error: Node.js is not installed")
        print("Install Node.js from: https://nodejs.org/")
        sys.exit(1)

    print("JavaScript Plugin Runner")
    print("=" * 60)

    # Lista plugins disponíveis
    plugins = runner.discover_js_plugins()

    if not plugins:
        print("No JavaScript plugins found in:", runner.plugins_dir)
        print("\nTo add JS plugins, create .js files in the js_plugins directory")
        print("Example plugin structure:")
        print("""
/**
 * @name xss_scanner
 * @description XSS vulnerability scanner
 * @category vuln_scan
 * @version 1.0.0
 */

const args = JSON.parse(process.argv[2] || '{}');
const target = args.target;

// Plugin logic here

console.log(JSON.stringify({
    success: true,
    findings: []
}));
""")
    else:
        print(f"Found {len(plugins)} JavaScript plugins:\n")
        for plugin in plugins:
            print(f"  [{plugin['category']}] {plugin['name']}")
            print(f"      {plugin['description']}")
            print(f"      File: {plugin['file']}\n")
