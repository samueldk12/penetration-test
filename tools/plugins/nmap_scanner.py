#!/usr/bin/env python3
"""
Nmap Scanner Plugin
Wrapper para ferramenta Nmap - Network scanner
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from pathlib import Path
import tempfile

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class NmapPlugin(PluginInterface):
    """Plugin para executar scans Nmap em alvos."""

    name = "nmap_scanner"
    version = "1.0.0"
    category = "recon"
    description = "Network scanner e service detection usando Nmap"

    def __init__(self):
        super().__init__()
        self.nmap_path = self._find_nmap()

    def _find_nmap(self) -> Optional[str]:
        """Encontra o executável do Nmap no sistema."""
        try:
            result = subprocess.run(['which', 'nmap'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Tenta caminhos comuns
        common_paths = [
            '/usr/bin/nmap',
            '/usr/local/bin/nmap'
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def run(self, target: str, **kwargs) -> Dict:
        """
        Executa scan Nmap no alvo.

        Args:
            target: IP, hostname ou CIDR
            **kwargs: Opções adicionais
                - scan_type: Tipo de scan (syn, tcp, udp, default: syn)
                - ports: Portas para scanear (default: top 1000)
                - service_detection: Detecta versões de serviços
                - os_detection: Detecta sistema operacional
                - script_scan: Executa scripts NSE
                - aggressive: Modo agressivo (-A)
                - timeout: Timeout do scan (default: 600)

        Returns:
            Dict com resultados do scan
        """
        if not self.nmap_path:
            return {
                'success': False,
                'error': 'Nmap not installed',
                'message': 'Install with: apt-get install nmap'
            }

        scan_type = kwargs.get('scan_type', 'syn')
        ports = kwargs.get('ports', '-')  # - = portas mais comuns
        service_detection = kwargs.get('service_detection', True)
        os_detection = kwargs.get('os_detection', False)
        script_scan = kwargs.get('script_scan', False)
        aggressive = kwargs.get('aggressive', False)
        timeout = kwargs.get('timeout', 600)

        # Cria arquivo temporário para output XML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
            output_file = tmp.name

        try:
            # Constrói comando Nmap
            cmd = [self.nmap_path, target]

            # Tipo de scan
            if aggressive:
                cmd.append('-A')
            else:
                if scan_type == 'syn':
                    cmd.append('-sS')
                elif scan_type == 'tcp':
                    cmd.append('-sT')
                elif scan_type == 'udp':
                    cmd.append('-sU')

                if service_detection:
                    cmd.append('-sV')

                if os_detection:
                    cmd.append('-O')

                if script_scan:
                    cmd.append('-sC')

            # Portas
            cmd.extend(['-p', ports])

            # Output XML
            cmd.extend(['-oX', output_file])

            # Outras opções
            cmd.extend(['-T4'])  # Timing template

            # Executa Nmap
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )

            # Parse do XML output
            scan_results = self._parse_nmap_xml(output_file)

            return {
                'success': True,
                'target': target,
                'scan_type': scan_type,
                'hosts': scan_results.get('hosts', []),
                'total_hosts': len(scan_results.get('hosts', [])),
                'total_open_ports': sum(len(h.get('ports', [])) for h in scan_results.get('hosts', [])),
                'scan_stats': scan_results.get('stats', {})
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Scan timeout',
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

    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse do output XML do Nmap."""
        results = {
            'hosts': [],
            'stats': {}
        }

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Parse hosts
            for host in root.findall('host'):
                host_data = self._parse_host(host)
                if host_data:
                    results['hosts'].append(host_data)

            # Parse stats
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    results['stats'] = {
                        'elapsed': finished.get('elapsed', ''),
                        'summary': finished.get('summary', ''),
                        'exit': finished.get('exit', '')
                    }

        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")

        return results

    def _parse_host(self, host_elem) -> Optional[Dict]:
        """Parse informações de um host."""
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None

        host_data = {
            'status': 'up',
            'addresses': [],
            'hostnames': [],
            'ports': [],
            'os': None
        }

        # Endereços IP
        for address in host_elem.findall('address'):
            host_data['addresses'].append({
                'addr': address.get('addr', ''),
                'type': address.get('addrtype', '')
            })

        # Hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name', ''),
                    'type': hostname.get('type', '')
                })

        # Portas
        ports = host_elem.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)

        # OS Detection
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_data['os'] = {
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', '')
                }

        return host_data

    def _parse_port(self, port_elem) -> Optional[Dict]:
        """Parse informações de uma porta."""
        state = port_elem.find('state')
        if state is None or state.get('state') != 'open':
            return None

        port_data = {
            'port': port_elem.get('portid', ''),
            'protocol': port_elem.get('protocol', ''),
            'state': 'open',
            'service': {}
        }

        # Service detection
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name', ''),
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'extrainfo': service.get('extrainfo', ''),
                'ostype': service.get('ostype', '')
            }

        # Scripts NSE
        scripts = []
        for script in port_elem.findall('script'):
            scripts.append({
                'id': script.get('id', ''),
                'output': script.get('output', '')
            })

        if scripts:
            port_data['scripts'] = scripts

        return port_data


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <target> [ports]")
        print("Example: python nmap_scanner.py 192.168.1.1 1-1000")
        sys.exit(1)

    plugin = NmapPlugin()
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else '-'

    print(f"Running Nmap scan on {target}...")
    result = plugin.run(target, ports=ports)

    print(json.dumps(result, indent=2))
