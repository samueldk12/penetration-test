#!/usr/bin/env python3
"""
Go Plugin Runner
Sistema para executar plugins Go compilados
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
import logging
import stat


class GoPluginRunner:
    """Executa plugins Go compilados."""

    def __init__(self, plugins_dir: str = None):
        self.plugins_dir = plugins_dir or str(Path(__file__).parent / 'go_plugins')
        self.go_path = self._find_go()
        self.logger = logging.getLogger(__name__)

    def _find_go(self) -> Optional[str]:
        """Encontra executável do Go."""
        try:
            result = subprocess.run(['which', 'go'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/go',
            '/usr/local/bin/go',
            '/usr/local/go/bin/go',
            '/opt/go/bin/go'
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def is_available(self) -> bool:
        """Verifica se Go está disponível."""
        return self.go_path is not None

    def discover_go_plugins(self) -> List[Dict]:
        """Descobre plugins Go disponíveis."""
        plugins = []

        if not os.path.exists(self.plugins_dir):
            self.logger.warning(f"Go plugins directory not found: {self.plugins_dir}")
            return plugins

        # Busca arquivos .go e binários compilados
        for item in Path(self.plugins_dir).iterdir():
            if item.is_file():
                # Binário compilado (executável)
                if os.access(item, os.X_OK) and not item.suffix:
                    plugin_info = self._get_plugin_info_from_binary(item)
                    if plugin_info:
                        plugins.append(plugin_info)
                # Código fonte .go
                elif item.suffix == '.go':
                    plugin_info = self._get_plugin_info_from_source(item)
                    if plugin_info:
                        plugins.append(plugin_info)

        return plugins

    def _get_plugin_info_from_binary(self, binary_file: Path) -> Optional[Dict]:
        """Extrai informações do binário Go."""
        try:
            # Tenta executar com --info flag
            result = subprocess.run(
                [str(binary_file), '--info'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                try:
                    info = json.loads(result.stdout)
                    return {
                        'name': info.get('name', binary_file.stem),
                        'file': str(binary_file),
                        'type': 'go_binary',
                        'description': info.get('description', ''),
                        'category': info.get('category', 'unknown'),
                        'version': info.get('version', '1.0.0'),
                        'compiled': True
                    }
                except json.JSONDecodeError:
                    pass

            # Fallback: usa nome do arquivo
            return {
                'name': binary_file.stem,
                'file': str(binary_file),
                'type': 'go_binary',
                'description': 'Go plugin (no metadata)',
                'category': 'unknown',
                'version': '1.0.0',
                'compiled': True
            }

        except Exception as e:
            self.logger.error(f"Error reading Go binary {binary_file}: {e}")
            return None

    def _get_plugin_info_from_source(self, source_file: Path) -> Optional[Dict]:
        """Extrai informações do código fonte Go."""
        try:
            with open(source_file, 'r') as f:
                lines = f.readlines()[:50]  # Primeiras 50 linhas

            metadata = {
                'name': source_file.stem,
                'file': str(source_file),
                'type': 'go_source',
                'description': '',
                'category': 'unknown',
                'version': '1.0.0',
                'compiled': False
            }

            # Parse de comentários de metadados
            for line in lines:
                line = line.strip()

                if line.startswith('// @name'):
                    metadata['name'] = line.split('// @name')[1].strip()
                elif line.startswith('// @description'):
                    metadata['description'] = line.split('// @description')[1].strip()
                elif line.startswith('// @category'):
                    metadata['category'] = line.split('// @category')[1].strip()
                elif line.startswith('// @version'):
                    metadata['version'] = line.split('// @version')[1].strip()

            return metadata

        except Exception as e:
            self.logger.error(f"Error reading Go source {source_file}: {e}")
            return None

    def compile_plugin(self, source_file: str) -> Optional[str]:
        """
        Compila plugin Go.

        Args:
            source_file: Path para arquivo .go

        Returns:
            Path do binário compilado ou None se falhar
        """
        if not self.go_path:
            self.logger.error("Go compiler not found")
            return None

        source_path = Path(source_file)
        if not source_path.exists():
            self.logger.error(f"Source file not found: {source_file}")
            return None

        # Nome do binário
        binary_path = source_path.parent / source_path.stem

        try:
            self.logger.info(f"Compiling {source_file}...")

            # Compila
            result = subprocess.run(
                [self.go_path, 'build', '-o', str(binary_path), str(source_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                # Torna executável
                os.chmod(binary_path, os.stat(binary_path).st_mode | stat.S_IEXEC)
                self.logger.info(f"Compiled successfully: {binary_path}")
                return str(binary_path)
            else:
                self.logger.error(f"Compilation failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Error compiling plugin: {e}")
            return None

    def run_plugin(self, plugin_file: str, target: str, **kwargs) -> Dict:
        """
        Executa plugin Go.

        Args:
            plugin_file: Path para binário ou source .go
            target: URL/domain alvo
            **kwargs: Argumentos adicionais

        Returns:
            Dict com resultados do plugin
        """
        plugin_path = Path(plugin_file)

        # Se é source, compila primeiro
        if plugin_path.suffix == '.go':
            binary = self.compile_plugin(plugin_file)
            if not binary:
                return {
                    'success': False,
                    'error': 'Failed to compile Go plugin'
                }
            plugin_path = Path(binary)

        if not plugin_path.exists():
            return {
                'success': False,
                'error': 'Plugin file not found',
                'file': plugin_file
            }

        # Verifica se é executável
        if not os.access(plugin_path, os.X_OK):
            return {
                'success': False,
                'error': 'Plugin is not executable',
                'file': plugin_file
            }

        try:
            # Prepara argumentos JSON
            args = {
                'target': target,
                **kwargs
            }

            args_json = json.dumps(args)

            # Executa plugin
            timeout = kwargs.get('timeout', 300)

            result = subprocess.run(
                [str(plugin_path), args_json],
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
                        'plugin': str(plugin_path),
                        'results': output
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'plugin': str(plugin_path),
                        'raw_output': result.stdout,
                        'note': 'Plugin did not return JSON'
                    }
            else:
                return {
                    'success': False,
                    'plugin': str(plugin_path),
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
        """Lista todos os plugins Go disponíveis."""
        plugins = self.discover_go_plugins()
        return [p['name'] for p in plugins]


if __name__ == "__main__":
    import sys

    runner = GoPluginRunner()

    if not runner.is_available():
        print("Error: Go compiler is not installed")
        print("Install Go from: https://golang.org/dl/")
        sys.exit(1)

    print("Go Plugin Runner")
    print("=" * 60)

    # Lista plugins disponíveis
    plugins = runner.discover_go_plugins()

    if not plugins:
        print("No Go plugins found in:", runner.plugins_dir)
        print("\nTo add Go plugins, create .go files in the go_plugins directory")
        print("Example plugin structure:")
        print("""
// @name port_scanner
// @description Fast port scanner
// @category recon
// @version 1.0.0

package main

import (
    "encoding/json"
    "fmt"
    "os"
)

type Args struct {
    Target string `json:"target"`
}

func main() {
    if len(os.Args) > 1 && os.Args[1] == "--info" {
        info := map[string]string{
            "name": "port_scanner",
            "description": "Fast port scanner",
            "category": "recon",
            "version": "1.0.0",
        }
        json.NewEncoder(os.Stdout).Encode(info)
        return
    }

    var args Args
    json.Unmarshal([]byte(os.Args[1]), &args)

    result := map[string]interface{}{
        "success": true,
        "findings": []string{},
    }
    json.NewEncoder(os.Stdout).Encode(result)
}
""")
    else:
        print(f"Found {len(plugins)} Go plugins:\n")
        for plugin in plugins:
            status = "✓ Compiled" if plugin['compiled'] else "⚠ Source only"
            print(f"  [{plugin['category']}] {plugin['name']} {status}")
            print(f"      {plugin['description']}")
            print(f"      File: {plugin['file']}\n")
