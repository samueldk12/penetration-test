#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) - Basic Level
=================================================

Aplicação: URL Fetcher / Web Proxy
Porta: 5040
Dificuldade: 🟢 Básico (10 pontos)

Vulnerabilidades:
- SSRF básico sem filtros
- Acesso a localhost
- Acesso a rede interna
- Protocol smuggling (file://)
- Cloud metadata access (simulado)

Objetivo:
1. Acessar serviços em localhost
2. Ler arquivos via file://
3. Acessar metadata (simulado)
4. Capturar flags

Dica: Nenhum filtro implementado - todas as URLs funcionam!
"""

from flask import Flask, request, render_template_string
import requests
import socket
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'basic-ssrf-lab-key'

# Simula serviços internos
INTERNAL_SERVICES = {
    8080: "Admin Panel - FLAG{ssrf_admin_access}",
    8081: "Database Manager - Super Secret Data",
    8082: "Internal API - {'api_key': 'sk-secret123', 'db_pass': 'root123'}",
}

# Simula cloud metadata
CLOUD_METADATA = {
    'instance-id': 'i-1234567890abcdef0',
    'instance-type': 't2.micro',
    'local-ipv4': '10.0.1.42',
    'public-ipv4': '54.123.45.67',
    'security-credentials': {
        'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
        'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'Token': 'AQoDYXdzEJr...truncated...',
        'Expiration': '2024-12-31T23:59:59Z',
        'FLAG': 'FLAG{ssrf_cloud_metadata_stolen}'
    }
}

def init_files():
    """Cria arquivos para file:// exploitation"""
    with open('/tmp/ssrf_secret.txt', 'w') as f:
        f.write('FLAG{ssrf_file_read_success}\n')
        f.write('Super secret configuration file!\n')
        f.write('Database: localhost:3306\n')
        f.write('Username: admin\n')
        f.write('Password: SuperSecretPass123!\n')

    print("[+] Secret files criados em /tmp/")


@app.route('/')
def index():
    """Página inicial"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Basic SSRF Lab - URL Fetcher</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Arial;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
            }
            .header {
                background: white;
                padding: 40px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            h1 {
                color: #667eea;
                margin-bottom: 10px;
            }
            .badge {
                background: #4caf50;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 12px;
            }
            .tool-box {
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            input[type="text"] {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }
            button {
                padding: 12px 30px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
            }
            button:hover {
                background: #5568d3;
            }
            .warning {
                background: #fff3cd;
                padding: 20px;
                border-radius: 5px;
                margin: 20px 0;
            }
            .info {
                background: #e3f2fd;
                padding: 20px;
                border-radius: 5px;
                margin: 20px 0;
            }
            code {
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🌐 URL Fetcher <span class="badge">BASIC SSRF LAB</span></h1>
                <p>Fetch and display content from any URL</p>
            </div>

            <div class="tool-box">
                <h2>Fetch URL</h2>
                <form method="POST" action="/fetch">
                    <input type="text" name="url" placeholder="Enter URL (e.g., https://google.com)" required>
                    <button type="submit">🔍 Fetch Content</button>
                </form>

                <div class="info" style="margin-top: 20px;">
                    <strong>ℹ️ What is this?</strong><br>
                    This tool fetches content from any URL and displays it.<br>
                    Useful for previewing web pages, APIs, and more.
                </div>
            </div>

            <div class="warning">
                <strong>🎯 Lab Objectives:</strong><br>
                1. Access localhost services (ports 8080, 8081, 8082)<br>
                2. Read local files using file:// protocol<br>
                3. Access simulated cloud metadata<br>
                4. Capture hidden flags<br>
                <br>
                <strong>💡 Hints:</strong><br>
                • Try: <code>http://localhost:8080/</code><br>
                • Try: <code>file:///tmp/ssrf_secret.txt</code><br>
                • Try: <code>http://169.254.169.254/metadata</code><br>
                • Try: <code>http://127.0.0.1:8082/</code>
            </div>

            <div class="tool-box">
                <h2>📚 Quick Links</h2>
                <p>
                    <a href="/services">📡 Internal Services</a> |
                    <a href="/metadata">☁️ Cloud Metadata</a> |
                    <a href="/about">📖 About</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    '''
    return html


@app.route('/fetch', methods=['POST'])
def fetch():
    """
    VULNERÁVEL: SSRF
    Faz request para qualquer URL sem validação
    """
    url = request.form.get('url', '')

    if not url:
        return '<h1>❌ Error</h1><p>URL é obrigatória</p><a href="/">← Back</a>', 400

    print(f"[DEBUG] Fetching URL: {url}")

    try:
        # VULNERÁVEL ❌ - Sem validação de URL!
        # Permite localhost, file://, qualquer protocolo

        # Detecta protocol
        if url.startswith('file://'):
            # File read
            filepath = url.replace('file://', '')
            try:
                with open(filepath, 'r') as f:
                    content = f.read()

                return f'''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>File Content</title>
                    <style>
                        body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                        h1 {{ color: #667eea; }}
                        pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; }}
                        .success {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                        a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>📄 File Content</h1>
                        <p><strong>File:</strong> <code>{filepath}</code></p>

                        <div class="success">
                            ✅ <strong>SSRF Successful!</strong> You read a local file using file:// protocol!
                        </div>

                        <pre>{content}</pre>

                        <a href="/">← Back to Home</a>
                    </div>
                </body>
                </html>
                '''
            except Exception as e:
                return f'<h1>Error reading file</h1><p>{str(e)}</p><a href="/">Back</a>', 500

        elif url.startswith('http://localhost:') or url.startswith('http://127.0.0.1:'):
            # Localhost access
            port = int(url.split(':')[-1].rstrip('/'))

            if port in INTERNAL_SERVICES:
                content = INTERNAL_SERVICES[port]

                return f'''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Internal Service</title>
                    <style>
                        body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                        h1 {{ color: #667eea; }}
                        .success {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                        .service-box {{ background: #f9f9f9; padding: 20px; border-radius: 5px; border-left: 4px solid #667eea; margin: 20px 0; }}
                        a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔓 Internal Service Accessed</h1>
                        <p><strong>URL:</strong> <code>{url}</code></p>

                        <div class="success">
                            ✅ <strong>SSRF Successful!</strong> You accessed an internal service!
                        </div>

                        <div class="service-box">
                            <h3>Service Response:</h3>
                            <p>{content}</p>
                        </div>

                        <a href="/">← Back to Home</a>
                    </div>
                </body>
                </html>
                '''
            else:
                return f'<h1>Service not found on port {port}</h1><a href="/">Back</a>', 404

        elif '169.254.169.254' in url or '/metadata' in url:
            # Cloud metadata (simulado)
            import json

            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Cloud Metadata</title>
                <style>
                    body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                    h1 {{ color: #667eea; }}
                    .danger {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                    pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                    a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>☁️ Cloud Metadata Exposed</h1>
                    <p><strong>URL:</strong> <code>{url}</code></p>

                    <div class="danger">
                        🚨 <strong>CRITICAL: Cloud Credentials Stolen!</strong><br>
                        In a real scenario, these credentials provide full access to cloud resources!
                    </div>

                    <h3>Instance Metadata:</h3>
                    <pre>{json.dumps(CLOUD_METADATA, indent=2)}</pre>

                    <a href="/">← Back to Home</a>
                </div>
            </body>
            </html>
            '''

        else:
            # HTTP request normal
            response = requests.get(url, timeout=5, allow_redirects=True)

            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Fetched Content</title>
                <style>
                    body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                    h1 {{ color: #667eea; }}
                    pre {{ background: #f9f9f9; padding: 20px; border-radius: 5px; overflow-x: auto; max-height: 500px; }}
                    a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>📄 Fetched Content</h1>
                    <p><strong>URL:</strong> {url}</p>
                    <p><strong>Status:</strong> {response.status_code}</p>
                    <p><strong>Content-Type:</strong> {response.headers.get('Content-Type', 'unknown')}</p>

                    <h3>Response:</h3>
                    <pre>{response.text[:5000]}</pre>

                    <a href="/">← Back</a>
                </div>
            </body>
            </html>
            '''

    except requests.Timeout:
        return '<h1>⏱️ Timeout</h1><p>Request demorou muito (> 5s)</p><a href="/">Back</a>', 504

    except requests.RequestException as e:
        return f'<h1>❌ Request Error</h1><p>{str(e)}</p><a href="/">Back</a>', 500

    except Exception as e:
        return f'<h1>❌ Error</h1><p>{str(e)}</p><a href="/">Back</a>', 500


@app.route('/services')
def services():
    """Lista de serviços internos"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Internal Services</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
            h1 { color: #667eea; }
            .service { background: #f9f9f9; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #667eea; }
            code { background: #f5f5f5; padding: 2px 8px; border-radius: 3px; }
            a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📡 Internal Services</h1>
            <p>These services are running on localhost and are NOT accessible from the internet.</p>

            <div class="service">
                <h3>Admin Panel</h3>
                <p><strong>Port:</strong> 8080</p>
                <p><strong>Access:</strong> <code>http://localhost:8080/</code></p>
                <p>Contains administrative tools and configurations.</p>
            </div>

            <div class="service">
                <h3>Database Manager</h3>
                <p><strong>Port:</strong> 8081</p>
                <p><strong>Access:</strong> <code>http://127.0.0.1:8081/</code></p>
                <p>Direct database access interface.</p>
            </div>

            <div class="service">
                <h3>Internal API</h3>
                <p><strong>Port:</strong> 8082</p>
                <p><strong>Access:</strong> <code>http://localhost:8082/</code></p>
                <p>Internal microservices API with credentials.</p>
            </div>

            <p style="margin-top: 30px;"><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    '''
    return html


@app.route('/metadata')
def metadata():
    """Info sobre cloud metadata"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Metadata</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
            h1 { color: #667eea; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
            code { background: #f5f5f5; padding: 2px 8px; border-radius: 3px; }
            pre { background: #2d2d2d; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>☁️ Cloud Metadata Service</h1>

            <div class="info">
                <strong>ℹ️ What is Cloud Metadata?</strong><br>
                Cloud providers (AWS, GCP, Azure) expose instance metadata via special IPs.<br>
                This metadata often contains sensitive information like IAM credentials!
            </div>

            <h3>Common Endpoints:</h3>
            <pre>
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
            </pre>

            <h3>Try accessing:</h3>
            <p><code>http://169.254.169.254/metadata</code> via the URL Fetcher!</p>

            <p style="margin-top: 30px;"><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    '''


@app.route('/about')
def about():
    """About lab"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About - SSRF Lab</title>
        <style>
            body { font-family: Arial; padding: 40px; max-width: 900px; margin: 0 auto; }
            h1 { color: #667eea; }
            .section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
            pre { background: #2d2d2d; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
            code { background: #f5f5f5; padding: 2px 8px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>ℹ️ About - Basic SSRF Lab</h1>

        <div class="section">
            <h2>🎯 Objectives</h2>
            <ul>
                <li>Understand SSRF fundamentals</li>
                <li>Access localhost services</li>
                <li>Read local files via file://</li>
                <li>Access cloud metadata (simulated)</li>
                <li>Capture hidden flags</li>
            </ul>
        </div>

        <div class="section">
            <h2>🚩 Flags</h2>
            <ul>
                <li><code>FLAG{ssrf_admin_access}</code> - via localhost:8080</li>
                <li><code>FLAG{ssrf_file_read_success}</code> - via file:///tmp/ssrf_secret.txt</li>
                <li><code>FLAG{ssrf_cloud_metadata_stolen}</code> - via 169.254.169.254</li>
            </ul>
        </div>

        <div class="section">
            <h2>💡 Example Payloads</h2>
            <pre>
# Localhost access
http://localhost:8080/
http://127.0.0.1:8081/
http://localhost:8082/

# File read
file:///etc/passwd
file:///tmp/ssrf_secret.txt

# Cloud metadata (simulated)
http://169.254.169.254/metadata

# Alternative localhost representations
http://127.1/
http://0.0.0.0/
http://[::1]/
            </pre>
        </div>

        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("=" * 80)
    print("SERVER-SIDE REQUEST FORGERY (SSRF) - BASIC LEVEL LAB")
    print("=" * 80)
    print("\n🌐 Aplicação: URL Fetcher / Web Proxy")
    print("\n🎯 Objetivos:")
    print("  1. Access localhost services (ports 8080, 8081, 8082)")
    print("  2. Read local files via file://")
    print("  3. Access cloud metadata (simulated)")
    print("  4. Capture all flags")
    print("\n🚩 Flags:")
    print("  - FLAG{ssrf_admin_access}")
    print("  - FLAG{ssrf_file_read_success}")
    print("  - FLAG{ssrf_cloud_metadata_stolen}")
    print("\n💡 Payloads:")
    print("  - http://localhost:8080/")
    print("  - file:///tmp/ssrf_secret.txt")
    print("  - http://169.254.169.254/metadata")
    print("\n" + "=" * 80)

    init_files()

    print("\n[+] Servidor rodando em http://localhost:5040")
    print("[*] Pressione Ctrl+C para parar\n")

    app.run(host='0.0.0.0', port=5040, debug=True)
