#!/usr/bin/env python3
"""
FFUF Fuzzer Plugin
Wrapper para ferramenta FFUF - Fast web fuzzer
"""

import subprocess
import json
from typing import Dict, List, Optional
from pathlib import Path
import tempfile

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class FFUFPlugin(PluginInterface):
    """Plugin para executar fuzzing com FFUF."""

    name = "ffuf_fuzzer"
    version = "1.0.0"
    category = "recon"
    description = "Fast web fuzzer usando FFUF"

    def __init__(self):
        super().__init__()
        self.ffuf_path = self._find_ffuf()

    def _find_ffuf(self) -> Optional[str]:
        """Encontra o executável do FFUF no sistema."""
        try:
            result = subprocess.run(['which', 'ffuf'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/ffuf',
            '/usr/local/bin/ffuf',
            '/go/bin/ffuf',
            str(Path.home() / 'go/bin/ffuf')
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa fuzzing com FFUF.

        Args:
            target: URL alvo (use FUZZ como placeholder)
            **kwargs: Opções adicionais
                - wordlist: Path da wordlist (obrigatório)
                - mode: Modo de fuzzing (dir, vhost, param, default: dir)
                - extensions: Extensões para testar (ex: php,html,txt)
                - match_codes: Códigos HTTP para match (default: 200,204,301,302,307,401,403,405)
                - filter_codes: Códigos HTTP para filtrar
                - filter_size: Filtra por tamanho de resposta
                - threads: Número de threads (default: 40)
                - timeout: Timeout do scan (default: 300)
                - recursion: Habilita recursão
                - recursion_depth: Profundidade da recursão

        Returns:
            Dict com resultados do fuzzing
        """
        if not self.ffuf_path:
            return {
                'success': False,
                'error': 'FFUF not installed',
                'message': 'Install from: https://github.com/ffuf/ffuf'
            }

        wordlist = kwargs.get('wordlist')
        if not wordlist:
            return {
                'success': False,
                'error': 'Wordlist required',
                'message': 'Specify wordlist path with wordlist parameter'
            }

        mode = kwargs.get('mode', 'dir')
        extensions = kwargs.get('extensions', '')
        match_codes = kwargs.get('match_codes', '200,204,301,302,307,401,403,405')
        filter_codes = kwargs.get('filter_codes', '')
        filter_size = kwargs.get('filter_size', '')
        threads = kwargs.get('threads', 40)
        timeout = kwargs.get('timeout', 300)
        recursion = kwargs.get('recursion', False)
        recursion_depth = kwargs.get('recursion_depth', 2)

        # Cria arquivo temporário para output JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            # Ajusta URL baseado no modo
            if mode == 'dir' and 'FUZZ' not in target:
                target = target.rstrip('/') + '/FUZZ'
            elif mode == 'vhost' and 'FUZZ' not in target:
                target = target.replace('://', '://FUZZ.')

            # Constrói comando FFUF
            cmd = [
                self.ffuf_path,
                '-u', target,
                '-w', wordlist,
                '-mc', match_codes,
                '-t', str(threads),
                '-o', output_file,
                '-of', 'json',
                '-timeout', '10',
                '-v'
            ]

            # Adiciona extensões
            if extensions:
                cmd.extend(['-e', extensions])

            # Filtros
            if filter_codes:
                cmd.extend(['-fc', filter_codes])

            if filter_size:
                cmd.extend(['-fs', str(filter_size)])

            # Recursão
            if recursion:
                cmd.extend(['-recursion', '-recursion-depth', str(recursion_depth)])

            # Mode específico
            if mode == 'vhost':
                cmd.extend(['-H', 'Host: FUZZ'])

            # Executa FFUF
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            # Parse do JSON output
            findings = self._parse_ffuf_json(output_file)

            return {
                'success': True,
                'target': target,
                'mode': mode,
                'findings': findings,
                'total_findings': len(findings),
                'status_code_breakdown': self._calculate_status_codes(findings)
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Fuzzing timeout',
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

    def _parse_ffuf_json(self, json_file: str) -> List[Dict]:
        """Parse do output JSON do FFUF."""
        findings = []

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            results = data.get('results', [])

            for result in results:
                finding = {
                    'url': result.get('url', ''),
                    'position': result.get('position', 0),
                    'status_code': result.get('status', 0),
                    'length': result.get('length', 0),
                    'words': result.get('words', 0),
                    'lines': result.get('lines', 0),
                    'content_type': result.get('content-type', ''),
                    'redirectlocation': result.get('redirectlocation', ''),
                    'input': result.get('input', {})
                }

                findings.append(finding)

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error parsing FFUF JSON: {e}")

        return findings

    def _calculate_status_codes(self, findings: List[Dict]) -> Dict:
        """Calcula breakdown de códigos de status."""
        breakdown = {}

        for finding in findings:
            status = finding.get('status_code', 0)
            breakdown[status] = breakdown.get(status, 0) + 1

        return breakdown


# Wordlists comuns
COMMON_WORDLISTS = {
    'common': '/usr/share/wordlists/dirb/common.txt',
    'big': '/usr/share/wordlists/dirb/big.txt',
    'dirbuster_medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    'dirbuster_small': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
    'raft_medium': '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    'raft_large': '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt'
}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ffuf_fuzzer.py <target_url> [wordlist]")
        print("Example: python ffuf_fuzzer.py https://example.com/FUZZ common")
        print("\nAvailable wordlists:")
        for name, path in COMMON_WORDLISTS.items():
            print(f"  {name}: {path}")
        sys.exit(1)

    plugin = FFUFPlugin()
    target = sys.argv[1]

    # Determina wordlist
    wordlist = None
    if len(sys.argv) > 2:
        wordlist_name = sys.argv[2]
        if wordlist_name in COMMON_WORDLISTS:
            wordlist = COMMON_WORDLISTS[wordlist_name]
        else:
            wordlist = wordlist_name

    if not wordlist:
        wordlist = COMMON_WORDLISTS.get('common')

    print(f"Running FFUF fuzzing on {target}...")
    print(f"Wordlist: {wordlist}")
    result = plugin.run(target, wordlist=wordlist)

    print(json.dumps(result, indent=2))
