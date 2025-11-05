#!/usr/bin/env python3
"""
Plugin Installer
Sistema para instalar plugins de repositórios GitHub
"""

import subprocess
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Optional, List
import logging
import re
from urllib.parse import urlparse


class PluginInstaller:
    """Instala plugins de repositórios externos."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir or Path(__file__).parent)
        self.plugins_dir = self.base_dir / 'plugins'
        self.js_plugins_dir = self.base_dir / 'js_plugins'
        self.go_plugins_dir = self.base_dir / 'go_plugins'
        self.logger = logging.getLogger(__name__)

        # Cria diretórios se não existem
        self.plugins_dir.mkdir(exist_ok=True)
        self.js_plugins_dir.mkdir(exist_ok=True)
        self.go_plugins_dir.mkdir(exist_ok=True)

    def install_from_url(self, url: str, **kwargs) -> Dict:
        """
        Instala plugin de uma URL.

        Suporta:
        - URLs GitHub (https://github.com/user/repo)
        - URLs diretas para arquivos (.py, .js, .go)
        - URLs de gist

        Args:
            url: URL do plugin/repositório
            **kwargs: Opções adicionais
                - plugin_type: 'python', 'javascript', 'go' (auto-detectado se não especificado)
                - name: Nome customizado para o plugin
                - force: Sobrescrever se já existe

        Returns:
            Dict com resultado da instalação
        """
        self.logger.info(f"Installing plugin from: {url}")

        # Detecta tipo de URL
        if 'github.com' in url:
            if '/blob/' in url or '/raw/' in url:
                # URL direta para arquivo
                return self._install_from_direct_url(url, **kwargs)
            elif 'gist.github.com' in url:
                # GitHub Gist
                return self._install_from_gist(url, **kwargs)
            else:
                # Repositório completo
                return self._install_from_github_repo(url, **kwargs)
        elif url.endswith(('.py', '.js', '.go')):
            # URL direta para arquivo
            return self._install_from_direct_url(url, **kwargs)
        else:
            return {
                'success': False,
                'error': 'Unsupported URL format',
                'message': 'Use GitHub URL, Gist URL, or direct file URL (.py, .js, .go)'
            }

    def _install_from_github_repo(self, url: str, **kwargs) -> Dict:
        """Instala plugins de um repositório GitHub completo."""
        # Parse URL
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')

        if len(path_parts) < 2:
            return {
                'success': False,
                'error': 'Invalid GitHub URL',
                'message': 'Expected format: https://github.com/user/repo'
            }

        user, repo = path_parts[0], path_parts[1]

        # Remove .git se presente
        repo = repo.replace('.git', '')

        self.logger.info(f"Cloning repository: {user}/{repo}")

        # Cria diretório temporário
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            try:
                # Clone repositório
                clone_url = f"https://github.com/{user}/{repo}.git"
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', clone_url, str(temp_path / repo)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode != 0:
                    return {
                        'success': False,
                        'error': 'Failed to clone repository',
                        'details': result.stderr
                    }

                repo_path = temp_path / repo

                # Descobre plugins no repositório
                installed = self._discover_and_install_plugins(repo_path, **kwargs)

                return {
                    'success': True,
                    'repository': f"{user}/{repo}",
                    'installed_plugins': installed,
                    'total': len(installed)
                }

            except subprocess.TimeoutExpired:
                return {
                    'success': False,
                    'error': 'Clone timeout'
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }

    def _install_from_direct_url(self, url: str, **kwargs) -> Dict:
        """Instala plugin de URL direta."""
        import requests

        # Converte GitHub blob URL para raw URL
        if 'github.com' in url and '/blob/' in url:
            url = url.replace('/blob/', '/raw/')

        # Detecta tipo de plugin
        plugin_type = kwargs.get('plugin_type')
        if not plugin_type:
            if url.endswith('.py'):
                plugin_type = 'python'
            elif url.endswith('.js'):
                plugin_type = 'javascript'
            elif url.endswith('.go'):
                plugin_type = 'go'
            else:
                return {
                    'success': False,
                    'error': 'Cannot determine plugin type',
                    'message': 'Specify plugin_type or use .py/.js/.go extension'
                }

        # Nome do plugin
        plugin_name = kwargs.get('name')
        if not plugin_name:
            plugin_name = Path(urlparse(url).path).name

        # Diretório de destino
        if plugin_type == 'python':
            dest_dir = self.plugins_dir
        elif plugin_type == 'javascript':
            dest_dir = self.js_plugins_dir
        elif plugin_type == 'go':
            dest_dir = self.go_plugins_dir
        else:
            return {
                'success': False,
                'error': f'Unknown plugin type: {plugin_type}'
            }

        dest_file = dest_dir / plugin_name

        # Verifica se já existe
        if dest_file.exists() and not kwargs.get('force', False):
            return {
                'success': False,
                'error': 'Plugin already exists',
                'file': str(dest_file),
                'message': 'Use --force to overwrite'
            }

        try:
            # Download arquivo
            self.logger.info(f"Downloading from {url}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Salva arquivo
            with open(dest_file, 'wb') as f:
                f.write(response.content)

            # Torna executável se necessário
            if plugin_type in ['javascript', 'go']:
                os.chmod(dest_file, 0o755)

            self.logger.info(f"Plugin installed: {dest_file}")

            # Para Go, tenta compilar
            if plugin_type == 'go':
                from go_plugin_runner import GoPluginRunner
                runner = GoPluginRunner()
                if runner.is_available():
                    binary = runner.compile_plugin(str(dest_file))
                    if binary:
                        self.logger.info(f"Go plugin compiled: {binary}")

            return {
                'success': True,
                'plugin_name': plugin_name,
                'plugin_type': plugin_type,
                'file': str(dest_file),
                'url': url
            }

        except requests.RequestException as e:
            return {
                'success': False,
                'error': 'Download failed',
                'details': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _install_from_gist(self, url: str, **kwargs) -> Dict:
        """Instala plugin de um GitHub Gist."""
        # Extrai gist ID
        gist_id = url.rstrip('/').split('/')[-1]

        # URL da API
        api_url = f"https://api.github.com/gists/{gist_id}"

        try:
            import requests
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()

            gist_data = response.json()
            files = gist_data.get('files', {})

            if not files:
                return {
                    'success': False,
                    'error': 'No files found in gist'
                }

            installed = []

            for filename, file_data in files.items():
                # Detecta tipo
                if filename.endswith('.py'):
                    plugin_type = 'python'
                elif filename.endswith('.js'):
                    plugin_type = 'javascript'
                elif filename.endswith('.go'):
                    plugin_type = 'go'
                else:
                    continue  # Ignora outros arquivos

                # URL do arquivo raw
                raw_url = file_data.get('raw_url')

                result = self._install_from_direct_url(
                    raw_url,
                    plugin_type=plugin_type,
                    name=filename,
                    **kwargs
                )

                if result['success']:
                    installed.append(filename)

            return {
                'success': True,
                'gist_id': gist_id,
                'installed_plugins': installed,
                'total': len(installed)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _discover_and_install_plugins(self, repo_path: Path, **kwargs) -> List[str]:
        """Descobre e instala plugins em um repositório."""
        installed = []

        # Padrões de busca
        patterns = {
            'python': ['**/*.py', 'plugins/**/*.py', 'src/**/*.py'],
            'javascript': ['**/*.js', 'plugins/**/*.js', 'src/**/*.js'],
            'go': ['**/*.go', 'plugins/**/*.go', 'src/**/*.go']
        }

        for plugin_type, glob_patterns in patterns.items():
            for pattern in glob_patterns:
                for file_path in repo_path.glob(pattern):
                    # Ignora arquivos de teste e __init__
                    if 'test' in file_path.stem.lower() or file_path.stem == '__init__':
                        continue

                    # Verifica se parece um plugin
                    if self._is_valid_plugin(file_path):
                        # Copia para diretório apropriado
                        if plugin_type == 'python':
                            dest_dir = self.plugins_dir
                        elif plugin_type == 'javascript':
                            dest_dir = self.js_plugins_dir
                        elif plugin_type == 'go':
                            dest_dir = self.go_plugins_dir

                        dest_file = dest_dir / file_path.name

                        # Verifica se já existe
                        if dest_file.exists() and not kwargs.get('force', False):
                            self.logger.warning(f"Skipping {file_path.name} (already exists)")
                            continue

                        # Copia arquivo
                        shutil.copy2(file_path, dest_file)

                        # Torna executável se necessário
                        if plugin_type in ['javascript', 'go']:
                            os.chmod(dest_file, 0o755)

                        installed.append(file_path.name)
                        self.logger.info(f"Installed: {file_path.name}")

        return installed

    def _is_valid_plugin(self, file_path: Path) -> bool:
        """Verifica se arquivo parece um plugin válido."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)  # Primeiros 500 chars

            # Busca por indicadores de plugin
            indicators = [
                '@name', '@description', '@category',  # Metadados
                'PluginInterface', 'class.*Plugin',    # Python
                'package main', 'func main',           # Go
            ]

            return any(re.search(indicator, content, re.IGNORECASE) for indicator in indicators)

        except Exception:
            return False

    def list_installed_plugins(self) -> Dict:
        """Lista todos os plugins instalados."""
        return {
            'python': [f.name for f in self.plugins_dir.glob('*.py')],
            'javascript': [f.name for f in self.js_plugins_dir.glob('*.js')],
            'go': [f.name for f in self.go_plugins_dir.glob('*') if f.is_file()]
        }

    def remove_plugin(self, plugin_name: str, plugin_type: str = None) -> Dict:
        """Remove um plugin instalado."""
        # Se tipo não especificado, busca em todos
        if not plugin_type:
            for ptype in ['python', 'javascript', 'go']:
                result = self.remove_plugin(plugin_name, ptype)
                if result['success']:
                    return result

            return {
                'success': False,
                'error': 'Plugin not found'
            }

        # Diretório baseado no tipo
        if plugin_type == 'python':
            plugin_file = self.plugins_dir / plugin_name
            if not plugin_name.endswith('.py'):
                plugin_file = self.plugins_dir / f"{plugin_name}.py"
        elif plugin_type == 'javascript':
            plugin_file = self.js_plugins_dir / plugin_name
            if not plugin_name.endswith('.js'):
                plugin_file = self.js_plugins_dir / f"{plugin_name}.js"
        elif plugin_type == 'go':
            plugin_file = self.go_plugins_dir / plugin_name
        else:
            return {
                'success': False,
                'error': f'Unknown plugin type: {plugin_type}'
            }

        if plugin_file.exists():
            plugin_file.unlink()

            # Remove binário compilado se Go
            if plugin_type == 'go':
                binary = plugin_file.with_suffix('')
                if binary.exists():
                    binary.unlink()

            return {
                'success': True,
                'plugin': plugin_name,
                'type': plugin_type
            }
        else:
            return {
                'success': False,
                'error': 'Plugin file not found',
                'file': str(plugin_file)
            }


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Plugin Installer')
    parser.add_argument('--add', metavar='URL', help='Install plugin from URL')
    parser.add_argument('--remove', metavar='NAME', help='Remove plugin')
    parser.add_argument('--list', action='store_true', help='List installed plugins')
    parser.add_argument('--type', choices=['python', 'javascript', 'go'],
                       help='Plugin type')
    parser.add_argument('--force', action='store_true',
                       help='Force overwrite if exists')

    args = parser.parse_args()

    installer = PluginInstaller()

    if args.add:
        print(f"Installing plugin from: {args.add}")
        result = installer.install_from_url(args.add, plugin_type=args.type, force=args.force)
        print(json.dumps(result, indent=2))

    elif args.remove:
        print(f"Removing plugin: {args.remove}")
        result = installer.remove_plugin(args.remove, args.type)
        print(json.dumps(result, indent=2))

    elif args.list:
        plugins = installer.list_installed_plugins()
        print("Installed Plugins:")
        print(json.dumps(plugins, indent=2))

    else:
        parser.print_help()
