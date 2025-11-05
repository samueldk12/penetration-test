#!/usr/bin/env python3
"""
Blacklist Manager - Sistema de blacklist para filtrar URLs e endpoints indesejados
Suporta: wildcards, regex, keywords, extensions
"""

import re
from typing import List, Set, Pattern
from pathlib import Path
import json


class BlacklistManager:
    """Gerenciador de blacklist para filtrar URLs."""

    def __init__(self, blacklist_file: str = "blacklist.json"):
        """
        Inicializa blacklist manager.

        Args:
            blacklist_file: Arquivo JSON com regras de blacklist
        """
        self.blacklist_file = blacklist_file

        # Sets para diferentes tipos de filtros
        self.keywords: Set[str] = set()
        self.extensions: Set[str] = set()
        self.regex_patterns: List[Pattern] = []
        self.exact_urls: Set[str] = set()

        # Blacklist padrão
        self._init_default_blacklist()

        # Carrega blacklist customizada se existe
        if Path(blacklist_file).exists():
            self.load_from_file(blacklist_file)

    def _init_default_blacklist(self):
        """Inicializa blacklist padrão."""

        # Keywords comuns para ignorar
        self.keywords = {
            # Static files
            'logout', 'signout', 'sign-out', 'logoff',

            # Noise endpoints
            'ping', 'healthz', 'health-check', 'status',
            'metrics', 'prometheus',

            # CDN/Static
            'cdn-cgi', 'static', 'assets', 'resources',
            'public', 'dist', 'build',

            # Dates (avoid scanning date-based URLs)
            '2020', '2021', '2022', '2023', '2024',

            # Common noise
            'javascript:', 'mailto:', 'tel:', 'data:',
            'void(0)', '#',
        }

        # Extensions para ignorar (arquivos estáticos)
        self.extensions = {
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.webp', '.tiff', '.psd',

            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.odt', '.ods', '.odp',

            # Media
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
            '.wav', '.ogg', '.m4a',

            # Archives
            '.zip', '.rar', '.tar', '.gz', '.7z', '.bz2',

            # Fonts
            '.woff', '.woff2', '.ttf', '.eot', '.otf',

            # Other static
            '.css', '.js', '.map', '.txt', '.xml', '.json',
        }

        # Regex patterns
        self.regex_patterns = [
            # UUIDs
            re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE),

            # Long numeric IDs
            re.compile(r'/\d{10,}'),

            # Timestamps
            re.compile(r'/\d{13}'),  # Unix timestamp milliseconds

            # Hashes (MD5, SHA1, SHA256)
            re.compile(r'/[0-9a-f]{32}', re.IGNORECASE),  # MD5
            re.compile(r'/[0-9a-f]{40}', re.IGNORECASE),  # SHA1

            # Base64-like long strings
            re.compile(r'/[A-Za-z0-9+/=]{50,}'),
        ]

    def add_keyword(self, keyword: str):
        """Adiciona keyword à blacklist."""
        self.keywords.add(keyword.lower())

    def add_extension(self, extension: str):
        """Adiciona extensão à blacklist."""
        if not extension.startswith('.'):
            extension = '.' + extension
        self.extensions.add(extension.lower())

    def add_regex(self, pattern: str):
        """Adiciona regex pattern à blacklist."""
        self.regex_patterns.append(re.compile(pattern, re.IGNORECASE))

    def add_exact_url(self, url: str):
        """Adiciona URL exata à blacklist."""
        self.exact_urls.add(url)

    def is_blacklisted(self, url: str) -> tuple[bool, str]:
        """
        Verifica se URL está na blacklist.

        Args:
            url: URL para verificar

        Returns:
            Tuple (is_blacklisted, reason)
        """
        url_lower = url.lower()

        # Verifica exact match
        if url in self.exact_urls:
            return True, "exact_match"

        # Verifica keywords
        for keyword in self.keywords:
            if keyword in url_lower:
                return True, f"keyword: {keyword}"

        # Verifica extensions
        for ext in self.extensions:
            if url_lower.endswith(ext):
                return True, f"extension: {ext}"

        # Verifica regex patterns
        for pattern in self.regex_patterns:
            if pattern.search(url):
                return True, f"pattern: {pattern.pattern[:50]}"

        return False, ""

    def filter_urls(self, urls: List[str], verbose: bool = False) -> List[str]:
        """
        Filtra lista de URLs removendo blacklisted.

        Args:
            urls: Lista de URLs
            verbose: Se True, mostra URLs filtradas

        Returns:
            Lista de URLs filtradas
        """
        filtered = []
        filtered_count = {}

        for url in urls:
            is_blacklisted, reason = self.is_blacklisted(url)

            if is_blacklisted:
                if verbose:
                    print(f"[FILTERED] {url} - Reason: {reason}")

                # Conta razões de filtro
                filtered_count[reason] = filtered_count.get(reason, 0) + 1
            else:
                filtered.append(url)

        if verbose and filtered_count:
            print(f"\n[*] Filtered {sum(filtered_count.values())} URLs:")
            for reason, count in sorted(filtered_count.items(), key=lambda x: x[1], reverse=True):
                print(f"    {reason}: {count}")

        return filtered

    def save_to_file(self, filename: str = None):
        """
        Salva blacklist em arquivo JSON.

        Args:
            filename: Nome do arquivo (opcional)
        """
        if filename is None:
            filename = self.blacklist_file

        data = {
            'keywords': list(self.keywords),
            'extensions': list(self.extensions),
            'regex_patterns': [p.pattern for p in self.regex_patterns],
            'exact_urls': list(self.exact_urls)
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Blacklist saved to {filename}")

    def load_from_file(self, filename: str):
        """
        Carrega blacklist de arquivo JSON.

        Args:
            filename: Nome do arquivo
        """
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            # Carrega keywords
            if 'keywords' in data:
                self.keywords.update(data['keywords'])

            # Carrega extensions
            if 'extensions' in data:
                self.extensions.update(data['extensions'])

            # Carrega regex patterns
            if 'regex_patterns' in data:
                for pattern in data['regex_patterns']:
                    self.regex_patterns.append(re.compile(pattern, re.IGNORECASE))

            # Carrega exact URLs
            if 'exact_urls' in data:
                self.exact_urls.update(data['exact_urls'])

            print(f"[+] Blacklist loaded from {filename}")
            print(f"    Keywords: {len(self.keywords)}")
            print(f"    Extensions: {len(self.extensions)}")
            print(f"    Regex patterns: {len(self.regex_patterns)}")
            print(f"    Exact URLs: {len(self.exact_urls)}")

        except FileNotFoundError:
            print(f"[!] Blacklist file not found: {filename}")
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON in blacklist file: {filename}")

    def clear(self):
        """Limpa toda a blacklist."""
        self.keywords.clear()
        self.extensions.clear()
        self.regex_patterns.clear()
        self.exact_urls.clear()

    def get_stats(self) -> dict:
        """Retorna estatísticas da blacklist."""
        return {
            'keywords': len(self.keywords),
            'extensions': len(self.extensions),
            'regex_patterns': len(self.regex_patterns),
            'exact_urls': len(self.exact_urls),
            'total_rules': len(self.keywords) + len(self.extensions) + len(self.regex_patterns) + len(self.exact_urls)
        }


# CLI Interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Blacklist Manager - Filter unwanted URLs")
    subparsers = parser.add_subparsers(dest='command', help='Command')

    # Filter URLs
    filter_parser = subparsers.add_parser('filter', help='Filter URLs from file or stdin')
    filter_parser.add_argument('input', nargs='?', help='Input file (or stdin if not provided)')
    filter_parser.add_argument('-o', '--output', help='Output file')
    filter_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    filter_parser.add_argument('-b', '--blacklist', default='blacklist.json', help='Blacklist file')

    # Add rules
    add_parser = subparsers.add_parser('add', help='Add rule to blacklist')
    add_parser.add_argument('type', choices=['keyword', 'extension', 'regex', 'url'], help='Rule type')
    add_parser.add_argument('value', help='Rule value')
    add_parser.add_argument('-b', '--blacklist', default='blacklist.json', help='Blacklist file')

    # Show stats
    stats_parser = subparsers.add_parser('stats', help='Show blacklist statistics')
    stats_parser.add_argument('-b', '--blacklist', default='blacklist.json', help='Blacklist file')

    # Export default
    export_parser = subparsers.add_parser('export', help='Export default blacklist')
    export_parser.add_argument('-o', '--output', default='blacklist_default.json', help='Output file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        exit(1)

    if args.command == 'filter':
        blacklist = BlacklistManager(args.blacklist if hasattr(args, 'blacklist') else 'blacklist.json')

        # Read URLs
        if args.input:
            with open(args.input, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        else:
            import sys
            urls = [line.strip() for line in sys.stdin if line.strip()]

        print(f"[*] Filtering {len(urls)} URLs...")
        filtered = blacklist.filter_urls(urls, verbose=args.verbose)

        print(f"[+] Kept {len(filtered)} URLs (filtered {len(urls) - len(filtered)})")

        # Output
        if args.output:
            with open(args.output, 'w') as f:
                f.write('\n'.join(filtered))
            print(f"[+] Saved to {args.output}")
        else:
            for url in filtered:
                print(url)

    elif args.command == 'add':
        blacklist = BlacklistManager(args.blacklist)

        if args.type == 'keyword':
            blacklist.add_keyword(args.value)
        elif args.type == 'extension':
            blacklist.add_extension(args.value)
        elif args.type == 'regex':
            blacklist.add_regex(args.value)
        elif args.type == 'url':
            blacklist.add_exact_url(args.value)

        blacklist.save_to_file()
        print(f"[+] Added {args.type}: {args.value}")

    elif args.command == 'stats':
        blacklist = BlacklistManager(args.blacklist)
        stats = blacklist.get_stats()

        print("\n=== BLACKLIST STATISTICS ===")
        print(f"Keywords: {stats['keywords']}")
        print(f"Extensions: {stats['extensions']}")
        print(f"Regex patterns: {stats['regex_patterns']}")
        print(f"Exact URLs: {stats['exact_urls']}")
        print(f"Total rules: {stats['total_rules']}")

    elif args.command == 'export':
        blacklist = BlacklistManager()
        blacklist.save_to_file(args.output)
        print(f"[+] Default blacklist exported to {args.output}")
