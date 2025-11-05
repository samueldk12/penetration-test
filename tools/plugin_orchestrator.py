#!/usr/bin/env python3
"""
Plugin Orchestrator
Orquestra execução de múltiplos plugins em paralelo
"""

import concurrent.futures
import time
import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from plugin_system import PluginManager
from js_plugin_runner import JSPluginRunner
from go_plugin_runner import GoPluginRunner
from discovery_storage import DiscoveryDatabase
from config_manager import ConfigManager
from notification_system import NotificationSystem


class PluginOrchestrator:
    """Orquestra execução de todos os plugins."""

    def __init__(self, config: ConfigManager, verbose: bool = False):
        self.config = config
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)

        # Setup logging
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )

        # Initialize managers
        self.plugin_manager = PluginManager()
        self.js_runner = JSPluginRunner()
        self.go_runner = GoPluginRunner()
        self.db = DiscoveryDatabase(config.get('general.database'))
        self.notifier = NotificationSystem(config.get('notifications', {}))

        # Discover plugins
        self.plugin_manager.discover_plugins()
        self.js_plugins = self.js_runner.discover_js_plugins() if self.js_runner.is_available() else []
        self.go_plugins = self.go_runner.discover_go_plugins() if self.go_runner.is_available() else []

        # Results storage
        self.results = {
            'start_time': None,
            'end_time': None,
            'elapsed_time': 0,
            'target': None,
            'plugins_run': 0,
            'plugins_success': 0,
            'plugins_failed': 0,
            'plugin_results': {},
            'summary': {}
        }

    def run_all_plugins(self, target: str, **kwargs) -> Dict:
        """
        Executa todos os plugins disponíveis no alvo.

        Args:
            target: URL/domain/IP alvo
            **kwargs: Opções adicionais
                - categories: Lista de categorias para executar
                - exclude_plugins: Lista de plugins para excluir
                - parallel: Número de plugins em paralelo (default: 3)

        Returns:
            Dict com resultados consolidados
        """
        self.results['start_time'] = datetime.now()
        self.results['target'] = target

        categories = kwargs.get('categories', self.config.get('plugins.enabled_categories'))
        exclude_plugins = kwargs.get('exclude_plugins', self.config.get('plugins.disabled_plugins'))
        parallel = kwargs.get('parallel', self.config.get('advanced.concurrent_scans'))

        self.logger.info(f"Starting comprehensive scan on: {target}")
        self.logger.info(f"Categories: {', '.join(categories)}")
        self.logger.info(f"Parallel scans: {parallel}")

        # Coleta plugins para executar
        plugins_to_run = []

        # Python plugins
        for category in categories:
            cat_plugins = self.plugin_manager.get_plugins_by_category(category)
            for plugin in cat_plugins:
                if plugin.name not in exclude_plugins:
                    plugins_to_run.append({
                        'type': 'python',
                        'plugin': plugin,
                        'name': plugin.name,
                        'category': category
                    })

        # JavaScript plugins
        for js_plugin in self.js_plugins:
            if js_plugin['category'] in categories and js_plugin['name'] not in exclude_plugins:
                plugins_to_run.append({
                    'type': 'javascript',
                    'plugin': js_plugin,
                    'name': js_plugin['name'],
                    'category': js_plugin['category']
                })

        # Go plugins
        for go_plugin in self.go_plugins:
            if go_plugin['category'] in categories and go_plugin['name'] not in exclude_plugins:
                plugins_to_run.append({
                    'type': 'go',
                    'plugin': go_plugin,
                    'name': go_plugin['name'],
                    'category': go_plugin['category']
                })

        self.logger.info(f"Total plugins to run: {len(plugins_to_run)}")

        # Executa plugins em paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {
                executor.submit(self._run_plugin_safe, p, target, **kwargs): p
                for p in plugins_to_run
            }

            for future in concurrent.futures.as_completed(futures):
                plugin_info = futures[future]
                try:
                    result = future.result()
                    self._process_plugin_result(plugin_info, result)
                except Exception as e:
                    self.logger.error(f"Plugin {plugin_info['name']} crashed: {e}")
                    self.results['plugins_failed'] += 1

        self.results['end_time'] = datetime.now()
        self.results['elapsed_time'] = (self.results['end_time'] - self.results['start_time']).total_seconds()

        # Gera resumo
        self._generate_summary()

        # Envia notificação de conclusão
        try:
            self.notifier.send_scan_complete(self.results['summary'])
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")

        return self.results

    def _run_plugin_safe(self, plugin_info: Dict, target: str, **kwargs) -> Dict:
        """Executa plugin com tratamento de erros."""
        plugin_name = plugin_info['name']
        plugin_type = plugin_info['type']

        self.logger.info(f"[{plugin_type.upper()}] Running: {plugin_name}")

        start_time = time.time()

        try:
            if plugin_type == 'python':
                result = plugin_info['plugin'].run(target, **kwargs)
            elif plugin_type == 'javascript':
                result = self.js_runner.run_plugin(
                    plugin_info['plugin']['file'],
                    target,
                    verbose=self.verbose,
                    **kwargs
                )
            elif plugin_type == 'go':
                result = self.go_runner.run_plugin(
                    plugin_info['plugin']['file'],
                    target,
                    verbose=self.verbose,
                    **kwargs
                )
            else:
                result = {'success': False, 'error': 'Unknown plugin type'}

            elapsed = time.time() - start_time

            self.logger.info(f"[{plugin_type.upper()}] {plugin_name} completed in {elapsed:.2f}s")

            return {
                'success': result.get('success', True),
                'result': result,
                'elapsed_time': elapsed
            }

        except Exception as e:
            elapsed = time.time() - start_time
            self.logger.error(f"[{plugin_type.upper()}] {plugin_name} failed: {e}")

            return {
                'success': False,
                'error': str(e),
                'elapsed_time': elapsed
            }

    def _process_plugin_result(self, plugin_info: Dict, result: Dict):
        """Processa resultado de um plugin."""
        plugin_name = plugin_info['name']

        self.results['plugins_run'] += 1

        if result['success']:
            self.results['plugins_success'] += 1
        else:
            self.results['plugins_failed'] += 1

        # Armazena resultado
        self.results['plugin_results'][plugin_name] = result

        # Salva dados no banco de dados
        self._save_to_database(plugin_info, result)

    def _save_to_database(self, plugin_info: Dict, result: Dict):
        """Salva resultados no banco de dados."""
        plugin_name = plugin_info['name']
        plugin_result = result.get('result', {})

        try:
            # Salva URLs descobertas
            if 'urls' in plugin_result:
                for url_data in plugin_result['urls']:
                    if isinstance(url_data, dict):
                        url = url_data.get('url', '')
                        domain = self._extract_domain(url)
                        self.db.add_url(
                            url,
                            domain,
                            discovered_by=plugin_name,
                            **url_data
                        )
                    elif isinstance(url_data, str):
                        domain = self._extract_domain(url_data)
                        self.db.add_url(url_data, domain, discovered_by=plugin_name)

            # Salva subdomínios
            if 'subdomains' in plugin_result:
                for subdomain in plugin_result['subdomains']:
                    if isinstance(subdomain, dict):
                        self.db.add_subdomain(
                            subdomain.get('subdomain', ''),
                            subdomain.get('root_domain', ''),
                            discovered_by=plugin_name,
                            **subdomain
                        )
                    elif isinstance(subdomain, str):
                        domain = subdomain.split('.', 1)[-1] if '.' in subdomain else subdomain
                        self.db.add_subdomain(subdomain, domain, discovered_by=plugin_name)

            # Salva vulnerabilidades
            if 'vulnerabilities' in plugin_result:
                for vuln in plugin_result['vulnerabilities']:
                    if isinstance(vuln, dict):
                        vuln_type = vuln.get('type', vuln.get('vuln_type', 'unknown'))
                        severity = vuln.get('severity', 'medium')
                        self.db.add_vulnerability(
                            vuln_type,
                            severity,
                            discovered_by=plugin_name,
                            **vuln
                        )

            # Salva secrets/API keys
            if 'secrets' in plugin_result or 'api_keys' in plugin_result:
                secrets = plugin_result.get('secrets', plugin_result.get('api_keys', []))
                for secret in secrets:
                    if isinstance(secret, dict):
                        self.db.add_secret(
                            secret.get('value', secret.get('secret_value', '')),
                            secret.get('type', secret.get('secret_type', 'unknown')),
                            discovered_by=plugin_name,
                            **secret
                        )

        except Exception as e:
            self.logger.error(f"Error saving {plugin_name} results to database: {e}")

    def _extract_domain(self, url: str) -> str:
        """Extrai domínio de uma URL."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url

    def _generate_summary(self):
        """Gera resumo dos resultados."""
        summary = {
            'total_plugins': self.results['plugins_run'],
            'successful': self.results['plugins_success'],
            'failed': self.results['plugins_failed'],
            'success_rate': (self.results['plugins_success'] / self.results['plugins_run'] * 100)
                           if self.results['plugins_run'] > 0 else 0,
            'total_time': self.results['elapsed_time']
        }

        # Estatísticas do banco de dados
        db_stats = self.db.get_statistics()
        summary.update({
            'total_urls_found': db_stats.get('total_urls', 0),
            'total_subdomains_found': db_stats.get('total_subdomains', 0),
            'total_secrets_found': db_stats.get('total_secrets', 0),
            'total_vulnerabilities_found': db_stats.get('total_vulnerabilities', 0)
        })

        self.results['summary'] = summary

    def print_summary(self):
        """Imprime resumo dos resultados."""
        summary = self.results['summary']

        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Target:           {self.results['target']}")
        print(f"Start Time:       {self.results['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"End Time:         {self.results['end_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration:   {summary['total_time']:.2f} seconds")
        print()
        print(f"Plugins Executed: {summary['total_plugins']}")
        print(f"  ✓ Successful:   {summary['successful']}")
        print(f"  ✗ Failed:       {summary['failed']}")
        print(f"  Success Rate:   {summary['success_rate']:.1f}%")
        print()
        print("FINDINGS:")
        print(f"  URLs:             {summary['total_urls_found']}")
        print(f"  Subdomains:       {summary['total_subdomains_found']}")
        print(f"  Secrets/API Keys: {summary['total_secrets_found']}")
        print(f"  Vulnerabilities:  {summary['total_vulnerabilities_found']}")
        print("=" * 70)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Plugin Orchestrator')
    parser.add_argument('target', help='Target URL/domain/IP')
    parser.add_argument('--config', default='config.yaml', help='Config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--categories', nargs='+', help='Plugin categories to run')
    parser.add_argument('--exclude', nargs='+', help='Plugins to exclude')
    parser.add_argument('--parallel', type=int, default=3, help='Concurrent plugins')

    args = parser.parse_args()

    # Load config
    config = ConfigManager(args.config)

    # Create orchestrator
    orchestrator = PluginOrchestrator(config, verbose=args.verbose)

    # Run all plugins
    kwargs = {}
    if args.categories:
        kwargs['categories'] = args.categories
    if args.exclude:
        kwargs['exclude_plugins'] = args.exclude
    if args.parallel:
        kwargs['parallel'] = args.parallel

    results = orchestrator.run_all_plugins(args.target, **kwargs)

    # Print summary
    orchestrator.print_summary()

    # Close database
    orchestrator.db.close()
