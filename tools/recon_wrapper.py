#!/usr/bin/env python3
"""
Recon Wrapper - Integra ferramentas externas com sistema de storage
Suporta: subfinder, amass, assetfinder, ffuf, gobuster, nuclei, etc.
"""

import subprocess
import json
import sys
import os
from typing import List, Dict, Optional
from pathlib import Path
import tempfile
import shutil

from discovery_storage import DiscoveryDatabase
from recon_integration import ReconIntegration
from secret_scanner import SecretScanner


class ReconWrapper:
    """Wrapper para ferramentas externas de reconnaissance."""

    def __init__(self, db_path: str = "recon_wrapper.db"):
        self.db = DiscoveryDatabase(db_path)
        self.recon = ReconIntegration(db_path=db_path)
        self.scanner = SecretScanner()
        self.db_path = db_path

    # ============================================
    # SUBDOMAIN ENUMERATION
    # ============================================

    def run_subfinder(self, domain: str, silent: bool = True) -> List[str]:
        """
        Executa subfinder para subdomain enumeration.

        Args:
            domain: Domínio alvo
            silent: Modo silencioso

        Returns:
            Lista de subdomínios descobertos
        """
        print(f"[*] Executando subfinder em {domain}...")

        # Verifica se subfinder está instalado
        if not shutil.which('subfinder'):
            print("[!] subfinder não encontrado. Instale: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return []

        try:
            cmd = ['subfinder', '-d', domain, '-all']
            if silent:
                cmd.append('-silent')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            print(f"[+] subfinder: {len(subdomains)} subdomínios encontrados")

            # Armazena no banco
            for subdomain in subdomains:
                self.db.add_subdomain(
                    subdomain=subdomain,
                    root_domain=domain,
                    discovered_by='subfinder'
                )

            return subdomains

        except FileNotFoundError:
            print("[!] subfinder não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] subfinder timeout (>5min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar subfinder: {e}")
            return []

    def run_amass(self, domain: str, passive: bool = True) -> List[str]:
        """
        Executa amass para subdomain enumeration.

        Args:
            domain: Domínio alvo
            passive: Modo passivo (não faz scan ativo)

        Returns:
            Lista de subdomínios descobertos
        """
        print(f"[*] Executando amass em {domain}...")

        if not shutil.which('amass'):
            print("[!] amass não encontrado. Instale: sudo apt install amass")
            return []

        try:
            cmd = ['amass', 'enum']
            if passive:
                cmd.append('-passive')

            cmd.extend(['-d', domain])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            print(f"[+] amass: {len(subdomains)} subdomínios encontrados")

            # Armazena no banco
            for subdomain in subdomains:
                self.db.add_subdomain(
                    subdomain=subdomain,
                    root_domain=domain,
                    discovered_by='amass'
                )

            return subdomains

        except FileNotFoundError:
            print("[!] amass não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] amass timeout (>10min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar amass: {e}")
            return []

    def run_assetfinder(self, domain: str) -> List[str]:
        """
        Executa assetfinder para subdomain enumeration.

        Args:
            domain: Domínio alvo

        Returns:
            Lista de subdomínios descobertos
        """
        print(f"[*] Executando assetfinder em {domain}...")

        if not shutil.which('assetfinder'):
            print("[!] assetfinder não encontrado. Instale: go install github.com/tomnomnom/assetfinder@latest")
            return []

        try:
            cmd = ['assetfinder', '--subs-only', domain]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            print(f"[+] assetfinder: {len(subdomains)} subdomínios encontrados")

            # Armazena no banco
            for subdomain in subdomains:
                self.db.add_subdomain(
                    subdomain=subdomain,
                    root_domain=domain,
                    discovered_by='assetfinder'
                )

            return subdomains

        except FileNotFoundError:
            print("[!] assetfinder não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] assetfinder timeout (>2min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar assetfinder: {e}")
            return []

    # ============================================
    # URL PROBING
    # ============================================

    def run_httpx(self, subdomains: List[str]) -> List[Dict]:
        """
        Executa httpx para probing de URLs.

        Args:
            subdomains: Lista de subdomínios

        Returns:
            Lista de URLs acessíveis com metadados
        """
        print(f"[*] Executando httpx em {len(subdomains)} subdomínios...")

        if not shutil.which('httpx'):
            print("[!] httpx não encontrado. Instale: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            return []

        try:
            # Cria arquivo temporário com subdomínios
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for sub in subdomains:
                    f.write(f"{sub}\n")
                temp_file = f.name

            # Executa httpx com JSON output
            cmd = [
                'httpx',
                '-l', temp_file,
                '-silent',
                '-json',
                '-title',
                '-status-code',
                '-content-length',
                '-tech-detect'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            urls = []
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    url_info = {
                        'url': data.get('url', ''),
                        'status_code': data.get('status_code', 0),
                        'content_length': data.get('content_length', 0),
                        'title': data.get('title', ''),
                        'tech': data.get('tech', []),
                        'webserver': data.get('webserver', '')
                    }
                    urls.append(url_info)

                    # Armazena URL no banco
                    from urllib.parse import urlparse
                    parsed = urlparse(url_info['url'])

                    self.db.add_url(
                        url=url_info['url'],
                        domain=parsed.netloc,
                        status_code=url_info['status_code'],
                        content_type='',
                        discovered_by='httpx'
                    )

                except json.JSONDecodeError:
                    continue

            # Remove arquivo temporário
            os.unlink(temp_file)

            print(f"[+] httpx: {len(urls)} URLs acessíveis")

            return urls

        except FileNotFoundError:
            print("[!] httpx não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] httpx timeout (>5min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar httpx: {e}")
            return []

    # ============================================
    # DIRECTORY/ENDPOINT FUZZING
    # ============================================

    def run_ffuf(self, base_url: str, wordlist: str = None) -> List[str]:
        """
        Executa ffuf para directory/endpoint fuzzing.

        Args:
            base_url: URL base
            wordlist: Path para wordlist (opcional)

        Returns:
            Lista de endpoints descobertos
        """
        print(f"[*] Executando ffuf em {base_url}...")

        if not shutil.which('ffuf'):
            print("[!] ffuf não encontrado. Instale: go install github.com/ffuf/ffuf/v2@latest")
            return []

        # Wordlist padrão
        if wordlist is None:
            # Procura por wordlists comuns
            common_wordlists = [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
            ]

            for wl in common_wordlists:
                if os.path.exists(wl):
                    wordlist = wl
                    break

            if wordlist is None:
                print("[!] Nenhuma wordlist encontrada. Especifique com --wordlist")
                return []

        try:
            # Cria arquivo de output temporário
            temp_output = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
            temp_output.close()

            # Monta URL com FUZZ
            fuzz_url = f"{base_url.rstrip('/')}/FUZZ"

            cmd = [
                'ffuf',
                '-u', fuzz_url,
                '-w', wordlist,
                '-mc', '200,204,301,302,307,401,403',
                '-o', temp_output.name,
                '-of', 'json',
                '-silent'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Le resultados
            endpoints = []
            try:
                with open(temp_output.name, 'r') as f:
                    data = json.load(f)

                    for result in data.get('results', []):
                        url = result.get('url', '')
                        status = result.get('status', 0)

                        endpoints.append(url)

                        # Armazena endpoint
                        from urllib.parse import urlparse
                        parsed = urlparse(url)

                        self.db.add_endpoint(
                            url=base_url,
                            endpoint=parsed.path,
                            method='GET',
                            status_code=status,
                            discovered_by='ffuf'
                        )

            except json.JSONDecodeError:
                pass

            # Remove arquivo temporário
            os.unlink(temp_output.name)

            print(f"[+] ffuf: {len(endpoints)} endpoints encontrados")

            return endpoints

        except FileNotFoundError:
            print("[!] ffuf não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] ffuf timeout (>5min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar ffuf: {e}")
            return []

    def run_gobuster(self, base_url: str, wordlist: str = None) -> List[str]:
        """
        Executa gobuster para directory brute force.

        Args:
            base_url: URL base
            wordlist: Path para wordlist (opcional)

        Returns:
            Lista de endpoints descobertos
        """
        print(f"[*] Executando gobuster em {base_url}...")

        if not shutil.which('gobuster'):
            print("[!] gobuster não encontrado. Instale: sudo apt install gobuster")
            return []

        # Wordlist padrão
        if wordlist is None:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            if not os.path.exists(wordlist):
                print("[!] Wordlist não encontrada. Especifique com --wordlist")
                return []

        try:
            cmd = [
                'gobuster', 'dir',
                '-u', base_url,
                '-w', wordlist,
                '-q',  # Quiet mode
                '--no-error'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            endpoints = []
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue

                # Parse linha (formato: /path (Status: 200) [Size: 1234])
                if '(Status:' in line:
                    path = line.split()[0]
                    url = f"{base_url.rstrip('/')}{path}"
                    endpoints.append(url)

                    # Armazena endpoint
                    from urllib.parse import urlparse
                    parsed = urlparse(url)

                    self.db.add_endpoint(
                        url=base_url,
                        endpoint=parsed.path,
                        method='GET',
                        discovered_by='gobuster'
                    )

            print(f"[+] gobuster: {len(endpoints)} endpoints encontrados")

            return endpoints

        except FileNotFoundError:
            print("[!] gobuster não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] gobuster timeout (>5min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar gobuster: {e}")
            return []

    # ============================================
    # VULNERABILITY SCANNING
    # ============================================

    def run_nuclei(self, urls: List[str], templates: str = None) -> List[Dict]:
        """
        Executa nuclei para vulnerability scanning.

        Args:
            urls: Lista de URLs
            templates: Path para templates (opcional)

        Returns:
            Lista de vulnerabilidades encontradas
        """
        print(f"[*] Executando nuclei em {len(urls)} URLs...")

        if not shutil.which('nuclei'):
            print("[!] nuclei não encontrado. Instale: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return []

        try:
            # Cria arquivo temporário com URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(f"{url}\n")
                temp_file = f.name

            # Cria arquivo de output temporário
            temp_output = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
            temp_output.close()

            cmd = [
                'nuclei',
                '-l', temp_file,
                '-json',
                '-o', temp_output.name,
                '-silent'
            ]

            if templates:
                cmd.extend(['-t', templates])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Le resultados
            vulnerabilities = []
            try:
                with open(temp_output.name, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue

                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue

            except Exception:
                pass

            # Remove arquivos temporários
            os.unlink(temp_file)
            os.unlink(temp_output.name)

            print(f"[+] nuclei: {len(vulnerabilities)} vulnerabilidades encontradas")

            return vulnerabilities

        except FileNotFoundError:
            print("[!] nuclei não encontrado no PATH")
            return []
        except subprocess.TimeoutExpired:
            print("[!] nuclei timeout (>10min)")
            return []
        except Exception as e:
            print(f"[!] Erro ao executar nuclei: {e}")
            return []

    # ============================================
    # WORKFLOW COMBINADO
    # ============================================

    def run_full_workflow(self, domain: str,
                         run_subdomain_tools: bool = True,
                         run_url_probing: bool = True,
                         run_endpoint_discovery: bool = True,
                         run_vuln_scan: bool = False) -> Dict:
        """
        Executa workflow completo com ferramentas externas.

        Args:
            domain: Domínio alvo
            run_subdomain_tools: Executar ferramentas de subdomain enumeration
            run_url_probing: Executar URL probing
            run_endpoint_discovery: Executar endpoint discovery
            run_vuln_scan: Executar vulnerability scanning

        Returns:
            Relatório com estatísticas
        """
        print("=" * 60)
        print(f"RECON WRAPPER - {domain}")
        print("=" * 60)

        all_subdomains = set()
        all_urls = []
        all_endpoints = []

        # FASE 1: Subdomain Enumeration
        if run_subdomain_tools:
            print("\n[FASE 1] SUBDOMAIN ENUMERATION")
            print("-" * 60)

            # subfinder
            subs = self.run_subfinder(domain)
            all_subdomains.update(subs)

            # assetfinder
            subs = self.run_assetfinder(domain)
            all_subdomains.update(subs)

            # amass (comentado por ser lento)
            # subs = self.run_amass(domain, passive=True)
            # all_subdomains.update(subs)

            print(f"\n[+] Total de subdomínios únicos: {len(all_subdomains)}")

        # FASE 2: URL Probing
        if run_url_probing and all_subdomains:
            print("\n[FASE 2] URL PROBING")
            print("-" * 60)

            urls = self.run_httpx(list(all_subdomains))
            all_urls.extend(urls)

        # FASE 3: Endpoint Discovery
        if run_endpoint_discovery and all_urls:
            print("\n[FASE 3] ENDPOINT DISCOVERY")
            print("-" * 60)

            # ffuf nas primeiras 5 URLs
            for url_data in all_urls[:5]:
                endpoints = self.run_ffuf(url_data['url'])
                all_endpoints.extend(endpoints)

        # FASE 4: Vulnerability Scanning (opcional)
        vulnerabilities = []
        if run_vuln_scan and all_urls:
            print("\n[FASE 4] VULNERABILITY SCANNING")
            print("-" * 60)

            urls_only = [u['url'] for u in all_urls]
            vulnerabilities = self.run_nuclei(urls_only)

        # FASE 5: Statistics
        print("\n[FASE 5] STATISTICS")
        print("-" * 60)

        stats = self.db.get_statistics()

        print(f"\nSubdomínios: {stats['total_subdomains']}")
        print(f"URLs: {stats['total_urls']}")
        print(f"Endpoints: {stats['total_endpoints']}")

        if vulnerabilities:
            print(f"Vulnerabilidades: {len(vulnerabilities)}")

        # Gera relatório
        report_file = f"recon_wrapper_{domain.replace('.', '_')}.json"
        self.recon.generate_report(report_file)

        print(f"\nRelatório salvo em: {report_file}")
        print(f"Banco de dados: {self.db_path}")

        return {
            'subdomains': len(all_subdomains),
            'urls': len(all_urls),
            'endpoints': len(all_endpoints),
            'vulnerabilities': len(vulnerabilities)
        }

    def close(self):
        """Fecha conexões."""
        self.recon.close()
        self.db.close()


# CLI Interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Recon Wrapper - Integra ferramentas externas (subfinder, amass, ffuf, etc.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ferramentas suportadas:
  Subdomain: subfinder, amass, assetfinder
  URL Probing: httpx
  Endpoints: ffuf, gobuster
  Vulnerabilities: nuclei

Exemplos:
  # Workflow completo
  python recon_wrapper.py example.com --full

  # Apenas subdomain enumeration
  python recon_wrapper.py example.com --subdomain

  # Subdomain + URL probing
  python recon_wrapper.py example.com --subdomain --url-probing
        """
    )

    parser.add_argument('domain', help='Domínio alvo')
    parser.add_argument('--full', action='store_true', help='Workflow completo (sem vuln scan)')
    parser.add_argument('--subdomain', action='store_true', help='Subdomain enumeration')
    parser.add_argument('--url-probing', action='store_true', help='URL probing')
    parser.add_argument('--endpoints', action='store_true', help='Endpoint discovery')
    parser.add_argument('--vuln-scan', action='store_true', help='Vulnerability scanning')
    parser.add_argument('--db', default='recon_wrapper.db', help='Banco SQLite')

    args = parser.parse_args()

    # Se --full, ativa tudo exceto vuln-scan
    if args.full:
        args.subdomain = True
        args.url_probing = True
        args.endpoints = True

    # Se nenhuma opção especificada, usa --subdomain
    if not (args.subdomain or args.url_probing or args.endpoints or args.vuln_scan):
        args.subdomain = True

    wrapper = ReconWrapper(db_path=args.db)

    try:
        wrapper.run_full_workflow(
            domain=args.domain,
            run_subdomain_tools=args.subdomain,
            run_url_probing=args.url_probing,
            run_endpoint_discovery=args.endpoints,
            run_vuln_scan=args.vuln_scan
        )
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário")
    except Exception as e:
        print(f"\n[!] Erro: {e}")
        import traceback
        traceback.print_exc()
    finally:
        wrapper.close()
