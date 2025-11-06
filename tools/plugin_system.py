#!/usr/bin/env python3
"""
Plugin System - Sistema modular para ferramentas de pentest
Permite adicionar/remover módulos dinamicamente
"""

import importlib
import importlib.util
import inspect
from typing import List, Dict, Any, Optional
from pathlib import Path
import json


class PluginInterface:
    """Interface base para todos os plugins."""

    # Metadata do plugin
    name: str = "base_plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "Base plugin interface"
    category: str = "general"  # recon, vuln_scan, exploitation, post_exploit
    requires: List[str] = []  # Dependências Python

    def __init__(self, config: Optional[Dict] = None):
        """
        Inicializa plugin.

        Args:
            config: Configuração do plugin
        """
        self.config = config or {}
        self.results = []
        self.errors = []

    def validate(self) -> bool:
        """
        Valida se o plugin pode ser executado.

        Returns:
            True se válido, False caso contrário
        """
        # Verifica dependências
        for dep in self.requires:
            try:
                importlib.import_module(dep)
            except ImportError:
                self.errors.append(f"Missing dependency: {dep}")
                return False

        return True

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Executa o plugin.

        Args:
            target: Alvo (URL, domínio, IP, etc.)
            **kwargs: Argumentos adicionais

        Returns:
            Dicionário com resultados
        """
        raise NotImplementedError("Plugin must implement run() method")

    def get_results(self) -> List[Dict]:
        """Retorna resultados da execução."""
        return self.results

    def get_errors(self) -> List[str]:
        """Retorna erros da execução."""
        return self.errors

    def to_dict(self) -> Dict:
        """Retorna metadados do plugin."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category,
            'requires': self.requires
        }


class PluginManager:
    """Gerenciador de plugins."""

    def __init__(self, plugins_dir: str = "plugins"):
        """
        Inicializa gerenciador.

        Args:
            plugins_dir: Diretório dos plugins
        """
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, PluginInterface] = {}
        self.categories: Dict[str, List[str]] = {}

        # Cria diretório se não existe
        self.plugins_dir.mkdir(exist_ok=True)

    def discover_plugins(self) -> int:
        """
        Descobre plugins no diretório.
        Procura por plugin.json em subdiretórios.

        Returns:
            Número de plugins descobertos
        """
        count = 0

        # Procura por arquivos plugin.json em subdiretórios
        for plugin_json in self.plugins_dir.rglob("plugin.json"):
            try:
                # Carrega metadados do plugin
                with open(plugin_json, 'r') as f:
                    metadata = json.load(f)

                # Verifica se é plugin Python
                if metadata.get('type') != 'python':
                    continue

                plugin_dir = plugin_json.parent
                entrypoint = metadata.get('entrypoint', f"{metadata['name']}.py")
                plugin_file = plugin_dir / entrypoint

                if not plugin_file.exists():
                    print(f"[!] Plugin entrypoint not found: {plugin_file}")
                    continue

                # Importa módulo
                module_name = f"plugin_{metadata['name']}"
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                if spec is None or spec.loader is None:
                    print(f"[!] Failed to load plugin spec: {plugin_file}")
                    continue

                module = importlib.util.module_from_spec(spec)

                # Adiciona diretório do plugin ao sys.path temporariamente
                import sys
                plugin_dir_str = str(plugin_dir)
                if plugin_dir_str not in sys.path:
                    sys.path.insert(0, plugin_dir_str)

                spec.loader.exec_module(module)

                # Procura por classes que herdam de PluginInterface
                plugin_instance = None
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, PluginInterface) and obj != PluginInterface:
                        plugin_instance = obj()

                        # Atualiza metadados do plugin com dados do JSON
                        plugin_instance.name = metadata.get('name', plugin_instance.name)
                        plugin_instance.version = metadata.get('version', plugin_instance.version)
                        plugin_instance.author = metadata.get('author', plugin_instance.author)
                        plugin_instance.description = metadata.get('description', plugin_instance.description)
                        plugin_instance.category = metadata.get('category', plugin_instance.category)

                        # Valida plugin
                        if plugin_instance.validate():
                            self.register_plugin(plugin_instance)
                            count += 1
                        else:
                            print(f"[!] Plugin {name} validation failed:")
                            for error in plugin_instance.get_errors():
                                print(f"    - {error}")
                        break

                if plugin_instance is None:
                    print(f"[!] No PluginInterface subclass found in {plugin_file}")

            except Exception as e:
                print(f"[!] Error loading plugin {plugin_json}: {e}")
                import traceback
                traceback.print_exc()

        # Também procura por arquivos Python soltos (compatibilidade com plugins antigos)
        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue

            try:
                # Importa módulo
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Procura por classes que herdam de PluginInterface
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, PluginInterface) and obj != PluginInterface:
                        plugin_instance = obj()

                        # Valida plugin
                        if plugin_instance.validate():
                            self.register_plugin(plugin_instance)
                            count += 1
                        else:
                            print(f"[!] Plugin {name} validation failed:")
                            for error in plugin_instance.get_errors():
                                print(f"    - {error}")

            except Exception as e:
                print(f"[!] Error loading plugin {plugin_file.name}: {e}")

        return count

    def register_plugin(self, plugin: PluginInterface) -> None:
        """
        Registra um plugin.

        Args:
            plugin: Instância do plugin
        """
        self.plugins[plugin.name] = plugin

        # Adiciona à categoria
        category = plugin.category
        if category not in self.categories:
            self.categories[category] = []

        self.categories[category].append(plugin.name)

        print(f"[+] Plugin registered: {plugin.name} ({plugin.category})")

    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """
        Obtém plugin por nome.

        Args:
            name: Nome do plugin

        Returns:
            Instância do plugin ou None
        """
        return self.plugins.get(name)

    def get_plugins_by_category(self, category: str) -> List[PluginInterface]:
        """
        Obtém plugins por categoria.

        Args:
            category: Categoria

        Returns:
            Lista de plugins
        """
        plugin_names = self.categories.get(category, [])
        return [self.plugins[name] for name in plugin_names]

    def list_plugins(self) -> List[Dict]:
        """
        Lista todos os plugins.

        Returns:
            Lista de metadados dos plugins
        """
        return [plugin.to_dict() for plugin in self.plugins.values()]

    def list_categories(self) -> Dict[str, int]:
        """
        Lista categorias e número de plugins.

        Returns:
            Dicionário {categoria: count}
        """
        return {cat: len(plugins) for cat, plugins in self.categories.items()}

    def run_plugin(self, name: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Executa um plugin.

        Args:
            name: Nome do plugin
            target: Alvo
            **kwargs: Argumentos adicionais

        Returns:
            Resultados da execução
        """
        plugin = self.get_plugin(name)

        if not plugin:
            return {'error': f'Plugin not found: {name}'}

        try:
            results = plugin.run(target, **kwargs)
            return {
                'plugin': name,
                'success': True,
                'results': results
            }
        except Exception as e:
            return {
                'plugin': name,
                'success': False,
                'error': str(e)
            }

    def run_category(self, category: str, target: str, **kwargs) -> List[Dict]:
        """
        Executa todos os plugins de uma categoria.

        Args:
            category: Categoria
            target: Alvo
            **kwargs: Argumentos adicionais

        Returns:
            Lista de resultados
        """
        plugins = self.get_plugins_by_category(category)
        results = []

        for plugin in plugins:
            print(f"[*] Running plugin: {plugin.name}")
            result = self.run_plugin(plugin.name, target, **kwargs)
            results.append(result)

        return results

    def run_all(self, target: str, **kwargs) -> Dict[str, List[Dict]]:
        """
        Executa todos os plugins.

        Args:
            target: Alvo
            **kwargs: Argumentos adicionais

        Returns:
            Dicionário {categoria: [resultados]}
        """
        all_results = {}

        for category in self.categories.keys():
            print(f"\n[*] Running category: {category}")
            results = self.run_category(category, target, **kwargs)
            all_results[category] = results

        return all_results

    def export_config(self, output_file: str) -> None:
        """
        Exporta configuração dos plugins.

        Args:
            output_file: Arquivo de saída
        """
        config = {
            'plugins': self.list_plugins(),
            'categories': self.list_categories()
        }

        with open(output_file, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"[+] Config exported to: {output_file}")


# CLI Interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Plugin System Manager")
    subparsers = parser.add_subparsers(dest='command', help='Command')

    # List plugins
    list_parser = subparsers.add_parser('list', help='List plugins')
    list_parser.add_argument('--category', help='Filter by category')

    # Run plugin
    run_parser = subparsers.add_parser('run', help='Run plugin')
    run_parser.add_argument('plugin', help='Plugin name')
    run_parser.add_argument('target', help='Target')
    run_parser.add_argument('--config', help='Config JSON file')

    # Run category
    run_cat_parser = subparsers.add_parser('run-category', help='Run all plugins in category')
    run_cat_parser.add_argument('category', help='Category name')
    run_cat_parser.add_argument('target', help='Target')

    # Run all
    run_all_parser = subparsers.add_parser('run-all', help='Run all plugins')
    run_all_parser.add_argument('target', help='Target')

    # Export config
    export_parser = subparsers.add_parser('export', help='Export plugin config')
    export_parser.add_argument('-o', '--output', default='plugins_config.json', help='Output file')

    # Common args
    parser.add_argument('--plugins-dir', default='plugins', help='Plugins directory')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        exit(1)

    # Initialize manager
    manager = PluginManager(plugins_dir=args.plugins_dir)
    count = manager.discover_plugins()

    print(f"[+] Discovered {count} plugins")

    if args.command == 'list':
        print("\n=== PLUGINS ===")

        if args.category:
            plugins = manager.get_plugins_by_category(args.category)
            for plugin in plugins:
                print(f"\n{plugin.name} ({plugin.version})")
                print(f"  Description: {plugin.description}")
                print(f"  Author: {plugin.author}")
                if plugin.requires:
                    print(f"  Requires: {', '.join(plugin.requires)}")
        else:
            categories = manager.list_categories()
            for category, count in categories.items():
                print(f"\n[{category}] ({count} plugins)")
                plugins = manager.get_plugins_by_category(category)
                for plugin in plugins:
                    print(f"  - {plugin.name}: {plugin.description}")

    elif args.command == 'run':
        print(f"\n[*] Running plugin: {args.plugin}")
        result = manager.run_plugin(args.plugin, args.target)

        print("\n=== RESULTS ===")
        print(json.dumps(result, indent=2))

    elif args.command == 'run-category':
        print(f"\n[*] Running category: {args.category}")
        results = manager.run_category(args.category, args.target)

        print("\n=== RESULTS ===")
        print(json.dumps(results, indent=2))

    elif args.command == 'run-all':
        print(f"\n[*] Running all plugins on: {args.target}")
        results = manager.run_all(args.target)

        print("\n=== RESULTS ===")
        print(json.dumps(results, indent=2))

    elif args.command == 'export':
        manager.export_config(args.output)
