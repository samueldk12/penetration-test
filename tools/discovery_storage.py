#!/usr/bin/env python3
"""
URL and Secrets Storage System
Armazena URLs, endpoints e secrets descobertos durante reconhecimento
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import hashlib


class DiscoveryDatabase:
    """Gerencia armazenamento de URLs e secrets descobertos."""

    def __init__(self, db_path: str = "recon_discoveries.db"):
        self.db_path = db_path
        self.conn = None
        self._init_database()

    def _init_database(self):
        """Inicializa estrutura do banco de dados."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()

        # Tabela de URLs descobertas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                path TEXT,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                discovered_by TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP,
                response_time FLOAT,
                headers TEXT,
                is_alive BOOLEAN DEFAULT 1,
                notes TEXT
            )
        """)

        # Tabela de endpoints/parâmetros
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                endpoint TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                parameters TEXT,
                discovered_by TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tested BOOLEAN DEFAULT 0,
                vulnerable BOOLEAN DEFAULT 0,
                vulnerability_type TEXT,
                notes TEXT,
                FOREIGN KEY (url_id) REFERENCES urls(id)
            )
        """)

        # Tabela de secrets/keys descobertas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                secret_type TEXT NOT NULL,
                secret_value TEXT NOT NULL,
                secret_hash TEXT UNIQUE,
                service TEXT,
                permissions_tested BOOLEAN DEFAULT 0,
                permissions_result TEXT,
                risk_level TEXT,
                discovered_by TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (url_id) REFERENCES urls(id)
            )
        """)

        # Tabela de subdomínios
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL UNIQUE,
                root_domain TEXT NOT NULL,
                ip_address TEXT,
                dns_records TEXT,
                discovered_by TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_alive BOOLEAN DEFAULT 1,
                last_checked TIMESTAMP,
                notes TEXT
            )
        """)

        # Tabela de testes de permissões
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permission_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_id INTEGER,
                test_type TEXT NOT NULL,
                test_result TEXT,
                permissions_found TEXT,
                risk_assessment TEXT,
                tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (secret_id) REFERENCES secrets(id)
            )
        """)

        # Tabela de vulnerabilidades
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                endpoint_id INTEGER,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                payload TEXT,
                evidence TEXT,
                cvss_score FLOAT,
                cve_id TEXT,
                discovered_by TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified BOOLEAN DEFAULT 0,
                false_positive BOOLEAN DEFAULT 0,
                remediation TEXT,
                notes TEXT,
                FOREIGN KEY (url_id) REFERENCES urls(id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            )
        """)

        # Índices para performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subdomains_root ON subdomains(root_domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type)")

        self.conn.commit()

    def add_url(self, url: str, domain: str, **kwargs) -> int:
        """
        Adiciona URL descoberta ao banco.

        Args:
            url: URL completa
            domain: Domínio base
            **kwargs: Metadados adicionais (status_code, content_type, etc.)

        Returns:
            ID da URL inserida
        """
        cursor = self.conn.cursor()

        # Extrai path da URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path if parsed.path else '/'

        data = {
            'url': url,
            'domain': domain,
            'path': path,
            'status_code': kwargs.get('status_code'),
            'content_type': kwargs.get('content_type'),
            'content_length': kwargs.get('content_length'),
            'discovered_by': kwargs.get('discovered_by', 'unknown'),
            'response_time': kwargs.get('response_time'),
            'headers': json.dumps(kwargs.get('headers', {})),
            'notes': kwargs.get('notes')
        }

        try:
            cursor.execute("""
                INSERT INTO urls (url, domain, path, status_code, content_type,
                                 content_length, discovered_by, response_time, headers, notes)
                VALUES (:url, :domain, :path, :status_code, :content_type,
                       :content_length, :discovered_by, :response_time, :headers, :notes)
            """, data)
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # URL já existe, retorna ID existente
            cursor.execute("SELECT id FROM urls WHERE url = ?", (url,))
            return cursor.fetchone()[0]

    def add_endpoint(self, url: str, endpoint: str, **kwargs) -> int:
        """
        Adiciona endpoint descoberto.

        Args:
            url: URL base
            endpoint: Path do endpoint
            **kwargs: method, parameters, etc.

        Returns:
            ID do endpoint inserido
        """
        cursor = self.conn.cursor()

        # Busca URL ID
        cursor.execute("SELECT id FROM urls WHERE url = ?", (url,))
        result = cursor.fetchone()
        url_id = result[0] if result else self.add_url(url, kwargs.get('domain', ''))

        data = {
            'url_id': url_id,
            'endpoint': endpoint,
            'method': kwargs.get('method', 'GET'),
            'parameters': json.dumps(kwargs.get('parameters', [])),
            'discovered_by': kwargs.get('discovered_by', 'unknown'),
            'notes': kwargs.get('notes')
        }

        cursor.execute("""
            INSERT INTO endpoints (url_id, endpoint, method, parameters, discovered_by, notes)
            VALUES (:url_id, :endpoint, :method, :parameters, :discovered_by, :notes)
        """, data)
        self.conn.commit()
        return cursor.lastrowid

    def add_secret(self, secret_value: str, secret_type: str, **kwargs) -> int:
        """
        Adiciona secret/key descoberta.

        Args:
            secret_value: Valor da secret
            secret_type: Tipo (aws_key, gcp_key, api_key, etc.)
            **kwargs: url, service, risk_level, etc.

        Returns:
            ID da secret inserida
        """
        cursor = self.conn.cursor()

        # Hash da secret para evitar duplicatas
        secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()

        # Busca URL ID se fornecida
        url_id = None
        if 'url' in kwargs:
            cursor.execute("SELECT id FROM urls WHERE url = ?", (kwargs['url'],))
            result = cursor.fetchone()
            url_id = result[0] if result else None

        data = {
            'url_id': url_id,
            'secret_type': secret_type,
            'secret_value': secret_value,
            'secret_hash': secret_hash,
            'service': kwargs.get('service'),
            'risk_level': kwargs.get('risk_level', 'unknown'),
            'discovered_by': kwargs.get('discovered_by', 'unknown'),
            'notes': kwargs.get('notes')
        }

        try:
            cursor.execute("""
                INSERT INTO secrets (url_id, secret_type, secret_value, secret_hash,
                                   service, risk_level, discovered_by, notes)
                VALUES (:url_id, :secret_type, :secret_value, :secret_hash,
                       :service, :risk_level, :discovered_by, :notes)
            """, data)
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Secret já existe
            cursor.execute("SELECT id FROM secrets WHERE secret_hash = ?", (secret_hash,))
            return cursor.fetchone()[0]

    def add_subdomain(self, subdomain: str, root_domain: str, **kwargs) -> int:
        """
        Adiciona subdomínio descoberto.

        Args:
            subdomain: Subdomínio completo
            root_domain: Domínio raiz
            **kwargs: ip_address, dns_records, etc.

        Returns:
            ID do subdomínio inserido
        """
        cursor = self.conn.cursor()

        data = {
            'subdomain': subdomain,
            'root_domain': root_domain,
            'ip_address': kwargs.get('ip_address'),
            'dns_records': json.dumps(kwargs.get('dns_records', {})),
            'discovered_by': kwargs.get('discovered_by', 'unknown'),
            'notes': kwargs.get('notes')
        }

        try:
            cursor.execute("""
                INSERT INTO subdomains (subdomain, root_domain, ip_address,
                                       dns_records, discovered_by, notes)
                VALUES (:subdomain, :root_domain, :ip_address,
                       :dns_records, :discovered_by, :notes)
            """, data)
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute("SELECT id FROM subdomains WHERE subdomain = ?", (subdomain,))
            return cursor.fetchone()[0]

    def add_permission_test(self, secret_id: int, test_type: str,
                          test_result: str, **kwargs) -> int:
        """
        Adiciona resultado de teste de permissões.

        Args:
            secret_id: ID da secret testada
            test_type: Tipo de teste (aws_iam, gcp_iam, etc.)
            test_result: Resultado do teste
            **kwargs: permissions_found, risk_assessment

        Returns:
            ID do teste inserido
        """
        cursor = self.conn.cursor()

        data = {
            'secret_id': secret_id,
            'test_type': test_type,
            'test_result': test_result,
            'permissions_found': json.dumps(kwargs.get('permissions_found', [])),
            'risk_assessment': kwargs.get('risk_assessment', 'unknown')
        }

        cursor.execute("""
            INSERT INTO permission_tests (secret_id, test_type, test_result,
                                         permissions_found, risk_assessment)
            VALUES (:secret_id, :test_type, :test_result,
                   :permissions_found, :risk_assessment)
        """, data)

        # Atualiza flag na tabela secrets
        cursor.execute("""
            UPDATE secrets
            SET permissions_tested = 1,
                permissions_result = ?
            WHERE id = ?
        """, (test_result, secret_id))

        self.conn.commit()
        return cursor.lastrowid

    def get_urls(self, domain: Optional[str] = None, alive_only: bool = False) -> List[Dict]:
        """Recupera URLs armazenadas."""
        cursor = self.conn.cursor()

        query = "SELECT * FROM urls WHERE 1=1"
        params = []

        if domain:
            query += " AND domain = ?"
            params.append(domain)

        if alive_only:
            query += " AND is_alive = 1"

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_secrets(self, secret_type: Optional[str] = None,
                   untested_only: bool = False) -> List[Dict]:
        """Recupera secrets armazenadas."""
        cursor = self.conn.cursor()

        query = "SELECT * FROM secrets WHERE 1=1"
        params = []

        if secret_type:
            query += " AND secret_type = ?"
            params.append(secret_type)

        if untested_only:
            query += " AND permissions_tested = 0"

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_subdomains(self, root_domain: Optional[str] = None) -> List[Dict]:
        """Recupera subdomínios armazenados."""
        cursor = self.conn.cursor()

        query = "SELECT * FROM subdomains WHERE 1=1"
        params = []

        if root_domain:
            query += " AND root_domain = ?"
            params.append(root_domain)

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict:
        """Retorna estatísticas do banco de dados."""
        cursor = self.conn.cursor()

        stats = {}

        # Total de URLs
        cursor.execute("SELECT COUNT(*) FROM urls")
        stats['total_urls'] = cursor.fetchone()[0]

        # Total de endpoints
        cursor.execute("SELECT COUNT(*) FROM endpoints")
        stats['total_endpoints'] = cursor.fetchone()[0]

        # Total de secrets
        cursor.execute("SELECT COUNT(*) FROM secrets")
        stats['total_secrets'] = cursor.fetchone()[0]

        # Secrets por tipo
        cursor.execute("""
            SELECT secret_type, COUNT(*) as count
            FROM secrets
            GROUP BY secret_type
        """)
        stats['secrets_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Secrets testadas
        cursor.execute("SELECT COUNT(*) FROM secrets WHERE permissions_tested = 1")
        stats['secrets_tested'] = cursor.fetchone()[0]

        # Total de subdomínios
        cursor.execute("SELECT COUNT(*) FROM subdomains")
        stats['total_subdomains'] = cursor.fetchone()[0]

        # Total de testes de permissões
        cursor.execute("SELECT COUNT(*) FROM permission_tests")
        stats['total_permission_tests'] = cursor.fetchone()[0]

        # Total de vulnerabilidades
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total_vulnerabilities'] = cursor.fetchone()[0]

        # Vulnerabilidades por severidade
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
        """)
        stats['vulnerabilities_by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Vulnerabilidades por tipo
        cursor.execute("""
            SELECT vuln_type, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY vuln_type
        """)
        stats['vulnerabilities_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}

        return stats

    def add_vulnerability(self, vuln_type: str, severity: str, **kwargs) -> int:
        """
        Adiciona vulnerabilidade descoberta.

        Args:
            vuln_type: Tipo de vulnerabilidade (xss, sqli, ssrf, etc.)
            severity: Severidade (critical, high, medium, low, info)
            **kwargs: url, endpoint_id, description, payload, evidence, etc.

        Returns:
            ID da vulnerabilidade inserida
        """
        cursor = self.conn.cursor()

        # Busca URL ID se fornecida
        url_id = None
        if 'url' in kwargs:
            cursor.execute("SELECT id FROM urls WHERE url = ?", (kwargs['url'],))
            result = cursor.fetchone()
            url_id = result[0] if result else None

        data = {
            'url_id': url_id,
            'endpoint_id': kwargs.get('endpoint_id'),
            'vuln_type': vuln_type,
            'severity': severity,
            'description': kwargs.get('description', ''),
            'payload': kwargs.get('payload', ''),
            'evidence': kwargs.get('evidence', ''),
            'cvss_score': kwargs.get('cvss_score'),
            'cve_id': kwargs.get('cve_id'),
            'discovered_by': kwargs.get('discovered_by', 'unknown'),
            'remediation': kwargs.get('remediation', ''),
            'notes': kwargs.get('notes', '')
        }

        cursor.execute("""
            INSERT INTO vulnerabilities (url_id, endpoint_id, vuln_type, severity,
                                       description, payload, evidence, cvss_score,
                                       cve_id, discovered_by, remediation, notes)
            VALUES (:url_id, :endpoint_id, :vuln_type, :severity,
                   :description, :payload, :evidence, :cvss_score,
                   :cve_id, :discovered_by, :remediation, :notes)
        """, data)

        self.conn.commit()
        return cursor.lastrowid

    def get_vulnerabilities(self, severity: Optional[str] = None,
                           vuln_type: Optional[str] = None) -> List[Dict]:
        """Recupera vulnerabilidades armazenadas."""
        cursor = self.conn.cursor()

        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if vuln_type:
            query += " AND vuln_type = ?"
            params.append(vuln_type)

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def export_to_json(self, output_file: str = "discoveries.json"):
        """Exporta todos os dados para JSON."""
        data = {
            'urls': self.get_urls(),
            'secrets': self.get_secrets(),
            'subdomains': self.get_subdomains(),
            'vulnerabilities': self.get_vulnerabilities(),
            'statistics': self.get_statistics(),
            'exported_at': datetime.now().isoformat()
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return output_file

    def close(self):
        """Fecha conexão com banco de dados."""
        if self.conn:
            self.conn.close()


# Exemplo de uso
if __name__ == "__main__":
    db = DiscoveryDatabase()

    # Adiciona URLs descobertas
    url_id = db.add_url(
        "https://api.example.com/v1/users",
        "example.com",
        status_code=200,
        content_type="application/json",
        discovered_by="subdomain_scanner"
    )

    # Adiciona endpoint
    db.add_endpoint(
        "https://api.example.com",
        "/v1/users",
        method="GET",
        parameters=["id", "name"],
        discovered_by="endpoint_scanner"
    )

    # Adiciona secret
    db.add_secret(
        "AKIA1234567890ABCDEF",
        "aws_access_key",
        service="aws",
        risk_level="high",
        discovered_by="secret_scanner"
    )

    # Estatísticas
    print(json.dumps(db.get_statistics(), indent=2))

    db.close()
