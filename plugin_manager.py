#!/usr/bin/env python3
"""
Plugin Manager CLI - Wrapper to avoid __main__ module issues
"""

import sys
from pathlib import Path

# Add tools to path
tools_dir = Path(__file__).parent / 'tools'
sys.path.insert(0, str(tools_dir))

# Now import and run the actual plugin system
from plugin_system import PluginManager
import json
import argparse

if __name__ == "__main__":
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
        sys.exit(1)

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
