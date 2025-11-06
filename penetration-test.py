#!/usr/bin/env python3
"""
Penetration Test Suite - Main CLI
Sistema completo de penetration testing com 18+ plugins
"""

import sys
import argparse
import logging
from pathlib import Path
import json

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent / 'tools'))

from config_manager import ConfigManager
from plugin_orchestrator import PluginOrchestrator
from plugin_system import PluginManager
from js_plugin_runner import JSPluginRunner
from go_plugin_runner import GoPluginRunner
from plugin_installer import PluginInstaller
from advanced_reporter import AdvancedReporter
from osint_module import OSINTModule
from discovery_storage import DiscoveryDatabase

__version__ = "2.0.0"


class PentestCLI:
    """Main CLI for Penetration Test Suite."""

    def __init__(self):
        self.config = None
        self.logger = logging.getLogger(__name__)

    def setup_logging(self, verbose: bool = False, debug: bool = False):
        """Configura sistema de logging."""
        if debug:
            level = logging.DEBUG
        elif verbose:
            level = logging.INFO
        else:
            level = logging.WARNING

        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def cmd_scan(self, args):
        """Comando: scan - Executa scan no alvo."""
        self.setup_logging(args.verbose, args.debug)

        # Load config
        self.config = ConfigManager(args.config)

        if not self.config.validate():
            print("❌ Invalid configuration. Fix errors and try again.")
            return 1

        # Create orchestrator
        orchestrator = PluginOrchestrator(self.config, verbose=args.verbose)

        # Prepare kwargs
        kwargs = {
            'timeout': args.timeout,
            'parallel': args.parallel
        }

        if args.categories:
            kwargs['categories'] = args.categories

        if args.exclude:
            kwargs['exclude_plugins'] = args.exclude

        # Run scan
        if args.all_plugins:
            print(f"🚀 Running ALL PLUGINS on: {args.target}")
            results = orchestrator.run_all_plugins(args.target, **kwargs)
        else:
            # Run specific plugin
            if args.plugin:
                plugin_manager = PluginManager()
                plugin_manager.discover_plugins()

                if args.plugin in plugin_manager.plugins:
                    plugin = plugin_manager.plugins[args.plugin]
                    print(f"🔧 Running plugin: {args.plugin}")
                    result = plugin.run(args.target, **kwargs)
                    print(json.dumps(result, indent=2))
                    return 0
                else:
                    print(f"❌ Plugin not found: {args.plugin}")
                    return 1
            else:
                results = orchestrator.run_all_plugins(args.target, **kwargs)

        # Print summary
        orchestrator.print_summary()

        # Generate report if requested
        if args.report or args.complete:
            self.cmd_report(argparse.Namespace(
                config=args.config,
                format=['json', 'html', 'markdown'] if args.complete else [args.report_format],
                type='comprehensive',
                output=args.output,
                filters={},
                verbose=args.verbose,
                debug=args.debug,
                domain=None,
                severity=None,
                vuln_type=None
            ))

        orchestrator.db.close()
        return 0

    def cmd_osint(self, args):
        """Comando: osint - Executa investigação OSINT."""
        self.setup_logging(args.verbose, args.debug)

        print(f"🕵️  Starting OSINT investigation on: {args.target}")

        osint = OSINTModule()
        results = osint.investigate(
            args.target,
            deep_scan=args.deep,
            include_breaches=not args.no_breaches,
            include_social=not args.no_social,
            include_documents=not args.no_documents
        )

        # Save report
        output_file = args.output or 'osint_report.json'
        osint.export_report(output_file)

        print(f"\n✅ OSINT report saved: {output_file}")

        # Print summary
        print("\n" + "=" * 60)
        print("OSINT SUMMARY")
        print("=" * 60)
        print(f"Target:      {results['target']}")
        print(f"Subdomains:  {len(results.get('subdomains', []))}")
        print(f"IPs:         {len(results.get('ip_addresses', []))}")
        print(f"Emails:      {len(results.get('email_addresses', []))}")
        print(f"Technologies: {len(results.get('technologies', []))}")
        print("=" * 60)

        return 0

    def cmd_report(self, args):
        """Comando: report - Gera relatórios."""
        self.setup_logging(args.verbose, args.debug)

        # Load config
        self.config = ConfigManager(args.config)
        db_path = self.config.get('general.database')

        reporter = AdvancedReporter(db_path)

        print(f"📊 Generating {args.type} report...")

        # Parse filters
        filters = {}
        if args.domain:
            filters['domain'] = args.domain
        if args.severity:
            filters['severity'] = args.severity
        if args.vuln_type:
            filters['vuln_type'] = args.vuln_type

        # Generate report
        if args.type == 'comprehensive':
            report = reporter.generate_comprehensive_report(**filters)
        else:
            report = reporter.generate_filtered_report(args.type, **filters)

        # Export reports
        for format in args.format:
            output_file = args.output or f'report.{format}'

            if not output_file.endswith(f'.{format}'):
                output_file = f'{output_file}.{format}'

            reporter.export_report(report, output_file, format=format)
            print(f"✅ {format.upper()} report saved: {output_file}")

        reporter.close()
        return 0

    def cmd_plugins(self, args):
        """Comando: plugins - Lista plugins disponíveis."""
        self.setup_logging(args.verbose, args.debug)

        # Python plugins
        plugin_manager = PluginManager()
        plugin_manager.discover_plugins()

        # JS plugins
        js_runner = JSPluginRunner()
        js_plugins = js_runner.discover_js_plugins() if js_runner.is_available() else []

        # Go plugins
        go_runner = GoPluginRunner()
        go_plugins = go_runner.discover_go_plugins() if go_runner.is_available() else []

        print("=" * 70)
        print("AVAILABLE PLUGINS")
        print("=" * 70)

        # Group by category
        categories = {}

        for name, plugin in plugin_manager.plugins.items():
            category = plugin.category
            if category not in categories:
                categories[category] = {'python': [], 'js': [], 'go': []}

            categories[category]['python'].append({
                'name': name,
                'description': plugin.description,
                'version': plugin.version
            })

        for js_plugin in js_plugins:
            category = js_plugin['category']
            if category not in categories:
                categories[category] = {'python': [], 'js': [], 'go': []}

            categories[category]['js'].append(js_plugin)

        for go_plugin in go_plugins:
            category = go_plugin['category']
            if category not in categories:
                categories[category] = {'python': [], 'js': [], 'go': []}

            categories[category]['go'].append(go_plugin)

        # Print by category
        for category in sorted(categories.keys()):
            print(f"\n📦 {category.upper()}")
            print("-" * 70)

            # Python plugins
            if categories[category]['python']:
                print("  Python Plugins:")
                for p in sorted(categories[category]['python'], key=lambda x: x['name']):
                    print(f"    • {p['name']} (v{p['version']})")
                    if args.verbose:
                        print(f"      {p['description']}")

            # JS plugins
            if categories[category]['js']:
                print("  JavaScript Plugins:")
                for p in sorted(categories[category]['js'], key=lambda x: x['name']):
                    print(f"    • {p['name']} (v{p['version']})")
                    if args.verbose:
                        print(f"      {p['description']}")

            # Go plugins
            if categories[category]['go']:
                print("  Go Plugins:")
                for p in sorted(categories[category]['go'], key=lambda x: x['name']):
                    status = "✓ Compiled" if p.get('compiled') else "⚠ Source"
                    print(f"    • {p['name']} (v{p['version']}) {status}")
                    if args.verbose:
                        print(f"      {p['description']}")

        # Summary
        total_python = len(plugin_manager.plugins)
        total_js = len(js_plugins)
        total_go = len(go_plugins)
        total = total_python + total_js + total_go

        print("\n" + "=" * 70)
        print(f"Total Plugins: {total} ({total_python} Python + {total_js} JavaScript + {total_go} Go)")
        print("=" * 70)

        return 0

    def cmd_add(self, args):
        """Comando: add - Instala plugin de URL."""
        self.setup_logging(args.verbose, args.debug)

        installer = PluginInstaller()

        print(f"📥 Installing plugin from: {args.url}")

        result = installer.install_from_url(
            args.url,
            plugin_type=args.type,
            force=args.force
        )

        if result['success']:
            print("\n✅ Plugin installed successfully!")
            print(f"   Type:     {result.get('type', 'unknown')}")
            print(f"   Location: {result.get('installed_path', 'unknown')}")

            if result.get('installed_plugins'):
                print(f"\n   Installed {len(result['installed_plugins'])} plugin(s):")
                for plugin in result['installed_plugins']:
                    print(f"     • {plugin}")
        else:
            print("\n❌ Installation failed")
            print(f"   Error: {result.get('error', 'Unknown error')}")
            if args.verbose:
                print(json.dumps(result, indent=2))
            return 1

        return 0

    def cmd_config(self, args):
        """Comando: config - Gerencia configurações."""
        if args.init:
            config = ConfigManager()
            config.create_default_config(args.output or 'config.yaml')
        elif args.show:
            config = ConfigManager(args.config)
            config.print_config()
        elif args.validate:
            config = ConfigManager(args.config)
            if config.validate():
                print("✅ Configuration is valid")
            else:
                print("❌ Configuration has errors")
                return 1
        else:
            print("Use --init, --show, or --validate")
            return 1

        return 0

    def cmd_stats(self, args):
        """Comando: stats - Mostra estatísticas do banco de dados."""
        self.config = ConfigManager(args.config)
        db_path = self.config.get('general.database')

        db = DiscoveryDatabase(db_path)
        stats = db.get_statistics()

        print("=" * 60)
        print("DATABASE STATISTICS")
        print("=" * 60)
        print(f"URLs:                 {stats['total_urls']}")
        print(f"Endpoints:            {stats['total_endpoints']}")
        print(f"Subdomains:           {stats['total_subdomains']}")
        print(f"Secrets/API Keys:     {stats['total_secrets']}")
        print(f"Vulnerabilities:      {stats.get('total_vulnerabilities', 0)}")
        print(f"Permission Tests:     {stats['total_permission_tests']}")

        if stats.get('secrets_by_type'):
            print("\nSecrets by Type:")
            for secret_type, count in sorted(stats['secrets_by_type'].items()):
                print(f"  {secret_type}: {count}")

        if stats.get('vulnerabilities_by_severity'):
            print("\nVulnerabilities by Severity:")
            for severity, count in sorted(stats['vulnerabilities_by_severity'].items()):
                print(f"  {severity}: {count}")

        print("=" * 60)

        db.close()
        return 0

    def cmd_web(self, args):
        """Comando: web - Inicia interface web."""
        try:
            # Import web server
            import web_server

            # Start server
            host = args.host
            port = args.port
            debug = args.debug

            print(f"🌐 Starting web interface on http://{host}:{port}")
            print("   Press Ctrl+C to stop")

            web_server.start_server(host=host, port=port, debug=debug)

        except KeyboardInterrupt:
            print("\n\n✓ Web server stopped")
            return 0
        except ImportError as e:
            print(f"❌ Error: Failed to import web server: {e}")
            print("   Install requirements: pip install flask flask-cors flask-socketio")
            return 1
        except Exception as e:
            print(f"❌ Error starting web server: {e}")
            return 1

    def main(self):
        """Main CLI entry point."""
        parser = argparse.ArgumentParser(
            description=f'Penetration Test Suite v{__version__}',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run all plugins on target
  %(prog)s scan example.com --all-plugins --complete --verbose

  # Run specific plugin
  %(prog)s scan example.com --plugin nuclei_scanner

  # Run only recon plugins
  %(prog)s scan example.com --categories recon

  # OSINT investigation
  %(prog)s osint example.com --deep

  # Generate comprehensive report
  %(prog)s report --type comprehensive --format json html markdown

  # List all available plugins
  %(prog)s plugins -v

  # Install plugin from GitHub
  %(prog)s add https://github.com/user/repo
  %(prog)s add https://raw.githubusercontent.com/user/repo/main/plugin.py

  # Initialize configuration
  %(prog)s config --init

  # View database statistics
  %(prog)s stats

For more information, visit: https://github.com/samueldk12/penetration-test
            """
        )

        parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan target with plugins')
        scan_parser.add_argument('target', help='Target URL/domain/IP')
        scan_parser.add_argument('--all-plugins', action='store_true',
                                help='Run ALL available plugins')
        scan_parser.add_argument('--plugin', help='Run specific plugin')
        scan_parser.add_argument('--categories', nargs='+',
                                help='Plugin categories to run (recon, vuln_scan)')
        scan_parser.add_argument('--exclude', nargs='+',
                                help='Plugins to exclude')
        scan_parser.add_argument('--complete', action='store_true',
                                help='Complete scan with all reports')
        scan_parser.add_argument('--parallel', type=int, default=3,
                                help='Concurrent plugin execution (default: 3)')
        scan_parser.add_argument('--timeout', type=int, default=300,
                                help='Plugin timeout in seconds (default: 300)')
        scan_parser.add_argument('--report', action='store_true',
                                help='Generate report after scan')
        scan_parser.add_argument('--report-format', default='json',
                                choices=['json', 'html', 'markdown'],
                                help='Report format (default: json)')
        scan_parser.add_argument('--output', help='Output file/directory')
        scan_parser.add_argument('--config', default='config.yaml',
                                help='Config file (default: config.yaml)')
        scan_parser.add_argument('--verbose', '-v', action='store_true',
                                help='Verbose output')
        scan_parser.add_argument('--debug', action='store_true',
                                help='Debug output')

        # OSINT command
        osint_parser = subparsers.add_parser('osint', help='OSINT investigation')
        osint_parser.add_argument('target', help='Target domain/email/name')
        osint_parser.add_argument('--deep', action='store_true',
                                 help='Deep OSINT scan')
        osint_parser.add_argument('--no-breaches', action='store_true',
                                 help='Skip breach checking')
        osint_parser.add_argument('--no-social', action='store_true',
                                 help='Skip social media search')
        osint_parser.add_argument('--no-documents', action='store_true',
                                 help='Skip document search')
        osint_parser.add_argument('--output', help='Output file')
        osint_parser.add_argument('--verbose', '-v', action='store_true')
        osint_parser.add_argument('--debug', action='store_true')

        # Report command
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_parser.add_argument('--type', default='comprehensive',
                                   choices=['comprehensive', 'vulnerabilities',
                                           'secrets', 'osint', 'recon', 'critical'],
                                   help='Report type (default: comprehensive)')
        report_parser.add_argument('--format', nargs='+',
                                   default=['json'],
                                   choices=['json', 'html', 'markdown'],
                                   help='Output formats (default: json)')
        report_parser.add_argument('--domain', help='Filter by domain')
        report_parser.add_argument('--severity',
                                   choices=['critical', 'high', 'medium', 'low', 'info'],
                                   help='Filter by severity')
        report_parser.add_argument('--vuln-type', help='Filter by vulnerability type')
        report_parser.add_argument('--output', help='Output file name')
        report_parser.add_argument('--config', default='config.yaml')
        report_parser.add_argument('--verbose', '-v', action='store_true')
        report_parser.add_argument('--debug', action='store_true')

        # Plugins command
        plugins_parser = subparsers.add_parser('plugins', help='List available plugins')
        plugins_parser.add_argument('--verbose', '-v', action='store_true',
                                   help='Show plugin descriptions')
        plugins_parser.add_argument('--debug', action='store_true')

        # Add command
        add_parser = subparsers.add_parser('add', help='Install plugin from URL')
        add_parser.add_argument('url', help='Plugin URL (GitHub repo, direct file, or Gist)')
        add_parser.add_argument('--type', choices=['python', 'javascript', 'go'],
                               help='Plugin type (auto-detected if not specified)')
        add_parser.add_argument('--force', action='store_true',
                               help='Overwrite if plugin exists')
        add_parser.add_argument('--verbose', '-v', action='store_true')
        add_parser.add_argument('--debug', action='store_true')

        # Config command
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_parser.add_argument('--init', action='store_true',
                                  help='Create default config file')
        config_parser.add_argument('--show', action='store_true',
                                  help='Show current configuration')
        config_parser.add_argument('--validate', action='store_true',
                                  help='Validate configuration')
        config_parser.add_argument('--output', help='Output file for --init')
        config_parser.add_argument('--config', default='config.yaml')

        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show database statistics')
        stats_parser.add_argument('--config', default='config.yaml')

        # Web command
        web_parser = subparsers.add_parser('web', help='Launch web interface')
        web_parser.add_argument('--host', default='127.0.0.1',
                               help='Host to bind to (default: 127.0.0.1)')
        web_parser.add_argument('--port', type=int, default=5000,
                               help='Port to bind to (default: 5000)')
        web_parser.add_argument('--debug', action='store_true',
                               help='Enable debug mode')

        # Parse arguments
        if len(sys.argv) == 1:
            parser.print_help()
            return 1

        args = parser.parse_args()

        # Route to command
        if args.command == 'scan':
            return self.cmd_scan(args)
        elif args.command == 'osint':
            return self.cmd_osint(args)
        elif args.command == 'report':
            return self.cmd_report(args)
        elif args.command == 'plugins':
            return self.cmd_plugins(args)
        elif args.command == 'add':
            return self.cmd_add(args)
        elif args.command == 'config':
            return self.cmd_config(args)
        elif args.command == 'stats':
            return self.cmd_stats(args)
        elif args.command == 'web':
            return self.cmd_web(args)
        else:
            parser.print_help()
            return 1


if __name__ == "__main__":
    cli = PentestCLI()
    sys.exit(cli.main())
