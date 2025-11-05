#!/usr/bin/env python3
"""
Command Injection - Basic Level
================================

Aplicação: Network Ping Utility
Porta: 5050
Dificuldade: 🟢 Básico (10 pontos)

Vulnerabilidades:
- OS Command Injection direto sem filtros
- Multiple injection points
- System information disclosure
- File reading via command injection

Objetivo:
1. Executar comandos básicos (whoami, id, ls)
2. Ler arquivos sensíveis (/etc/passwd)
3. Obter informações do sistema
4. Capturar flags

Dica: Nenhum filtro implementado - todos os comandos funcionam!
"""

from flask import Flask, request, render_template_string, make_response
import subprocess
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'basic-command-injection-key'

# Flag escondida em arquivo
FLAG_FILE = '/tmp/flag.txt'

def init_flags():
    """Cria arquivos com flags"""
    with open(FLAG_FILE, 'w') as f:
        f.write('FLAG{basic_command_injection_success}\n')
        f.write('Congratulations! You found the flag via command injection!\n')

    # Cria arquivo de configuração simulado
    with open('/tmp/config.conf', 'w') as f:
        f.write('DATABASE_PASSWORD=SuperSecret123!\n')
        f.write('API_KEY=sk-1234567890abcdef\n')
        f.write('ADMIN_TOKEN=admin_token_secret_xyz\n')

    print("[+] Flags criadas em /tmp/")


@app.route('/')
def index():
    """Página inicial com ping utility"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Basic Command Injection Lab - Ping Utility</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Arial;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 900px;
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
            pre {
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                margin: 10px 0;
            }
            code {
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }
            a {
                color: #667eea;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🌐 Network Ping Utility <span class="badge">BASIC LAB</span></h1>
                <p>Test network connectivity to any host</p>
            </div>

            <div class="tool-box">
                <h2>Ping Tool</h2>
                <form method="POST" action="/ping">
                    <input type="text" name="ip" placeholder="Enter IP or hostname (e.g., 8.8.8.8)" required>
                    <button type="submit">🔍 Ping</button>
                </form>

                <div class="info" style="margin-top: 20px;">
                    <strong>ℹ️ Sobre:</strong><br>
                    Esta ferramenta envia 4 pacotes ICMP para o host especificado.<br>
                    Útil para verificar conectividade de rede e latência.
                </div>
            </div>

            <div class="warning">
                <strong>🎯 Objetivo do Lab:</strong><br>
                1. Execute comandos básicos (whoami, id, ls)<br>
                2. Leia arquivos sensíveis (/etc/passwd, /tmp/flag.txt)<br>
                3. Obtenha informações do sistema<br>
                4. Capture as flags escondidas<br>
                <br>
                <strong>💡 Dica:</strong> Nenhum filtro implementado! Teste separadores como <code>;</code>, <code>&&</code>, <code>||</code>
            </div>

            <div class="tool-box">
                <h2>📚 Outros Tools</h2>
                <p>
                    <a href="/traceroute">🔍 Traceroute</a> |
                    <a href="/nslookup">📡 DNS Lookup</a> |
                    <a href="/whois">ℹ️ Whois</a> |
                    <a href="/about">📖 About</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    '''
    return html


@app.route('/ping', methods=['POST'])
def ping():
    """
    VULNERÁVEL: Command Injection
    Executa comando ping sem sanitização
    """
    ip = request.form.get('ip', '127.0.0.1')

    # VULNERÁVEL ❌ - Concatenação direta + shell=True
    command = f'ping -c 4 {ip}'

    print(f"[DEBUG] Executando comando: {command}")

    try:
        # VULNERÁVEL ❌
        result = subprocess.run(
            command,
            shell=True,  # Permite command injection!
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + result.stderr

        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ping Result</title>
            <style>
                body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                h1 {{ color: #667eea; }}
                pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New'; }}
                .back {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
                .warning {{ background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📡 Ping Result</h1>
                <p><strong>Command executed:</strong> <code>{command}</code></p>
                <pre>{output}</pre>

                <div class="warning">
                    <strong>💡 Você executou:</strong> <code>{command}</code><br>
                    <strong>🎯 Próximo passo:</strong> Tente injetar comandos adicionais!<br>
                    Exemplos:<br>
                    • <code>8.8.8.8; whoami</code><br>
                    • <code>8.8.8.8 && id</code><br>
                    • <code>8.8.8.8 || cat /etc/passwd</code><br>
                    • <code>8.8.8.8; cat /tmp/flag.txt</code>
                </div>

                <a href="/" class="back">← Voltar</a>
            </div>
        </body>
        </html>
        '''

        return html

    except subprocess.TimeoutExpired:
        return '''
        <h1>⏱️ Timeout</h1>
        <p>Comando demorou muito tempo (> 10 segundos)</p>
        <a href="/">← Voltar</a>
        ''', 504

    except Exception as e:
        return f'''
        <h1>❌ Erro</h1>
        <p>Erro ao executar comando: {str(e)}</p>
        <a href="/">← Voltar</a>
        ''', 500


@app.route('/traceroute')
def traceroute():
    """Traceroute tool - também vulnerável"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Traceroute Tool</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
            h1 { color: #667eea; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; }
            button { padding: 12px 30px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Traceroute Tool</h1>
            <form method="POST" action="/traceroute/run">
                <input type="text" name="host" placeholder="Enter hostname or IP" required>
                <button type="submit">Trace Route</button>
            </form>

            <div class="info">
                <strong>ℹ️ About Traceroute:</strong><br>
                Shows the route packets take to reach a destination.<br>
                Useful for diagnosing network problems.
            </div>

            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    '''
    return html


@app.route('/traceroute/run', methods=['POST'])
def traceroute_run():
    """VULNERÁVEL: Command injection no traceroute"""
    host = request.form.get('host', '8.8.8.8')

    # VULNERÁVEL ❌
    command = f'traceroute -m 10 {host}'

    print(f"[DEBUG] Traceroute command: {command}")

    try:
        result = subprocess.run(
            command,
            shell=True,  # VULNERÁVEL!
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout + result.stderr

        return f'''
        <html>
        <head>
            <title>Traceroute Result</title>
            <style>
                body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Traceroute Result</h1>
                <p><strong>Command:</strong> <code>{command}</code></p>
                <pre>{output}</pre>
                <a href="/traceroute">← Back</a>
            </div>
        </body>
        </html>
        '''

    except Exception as e:
        return f'<h1>Error:</h1><p>{str(e)}</p><a href="/traceroute">Back</a>', 500


@app.route('/nslookup')
def nslookup():
    """DNS lookup tool - também vulnerável"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DNS Lookup</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
            h1 { color: #667eea; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; }
            button { padding: 12px 30px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📡 DNS Lookup Tool</h1>
            <form method="POST" action="/nslookup/run">
                <input type="text" name="domain" placeholder="Enter domain name" required>
                <button type="submit">Lookup</button>
            </form>
            <p style="margin-top: 20px;"><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    '''
    return html


@app.route('/nslookup/run', methods=['POST'])
def nslookup_run():
    """VULNERÁVEL: Command injection no nslookup"""
    domain = request.form.get('domain', 'google.com')

    # VULNERÁVEL ❌
    command = f'nslookup {domain}'

    print(f"[DEBUG] Nslookup command: {command}")

    try:
        result = subprocess.run(
            command,
            shell=True,  # VULNERÁVEL!
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + result.stderr

        return f'''
        <html>
        <head>
            <title>DNS Lookup Result</title>
            <style>
                body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
                pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; }}
                a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📡 DNS Lookup Result</h1>
                <p><strong>Command:</strong> <code>{command}</code></p>
                <pre>{output}</pre>
                <a href="/nslookup">← Back</a>
            </div>
        </body>
        </html>
        '''

    except Exception as e:
        return f'<h1>Error:</h1><p>{str(e)}</p><a href="/nslookup">Back</a>', 500


@app.route('/whois')
def whois():
    """Whois lookup - também vulnerável"""
    return '''
    <html>
    <head>
        <title>Whois Lookup</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; }
            button { padding: 12px 30px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ℹ️ Whois Lookup</h1>
            <form method="POST" action="/whois/run">
                <input type="text" name="domain" placeholder="Enter domain" required>
                <button type="submit">Lookup</button>
            </form>
            <p style="margin-top: 20px;"><a href="/">← Back</a></p>
        </div>
    </body>
    </html>
    '''


@app.route('/whois/run', methods=['POST'])
def whois_run():
    """VULNERÁVEL: Command injection no whois"""
    domain = request.form.get('domain', 'google.com')

    # VULNERÁVEL ❌
    command = f'whois {domain}'

    print(f"[DEBUG] Whois command: {command}")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout + result.stderr

        return f'''
        <html>
        <head><title>Whois Result</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
            pre {{ background: #2d2d2d; color: #0f0; padding: 20px; border-radius: 5px; overflow-x: auto; }}
            a {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
        </style>
        </head>
        <body>
            <div class="container">
                <h1>ℹ️ Whois Result</h1>
                <p><strong>Command:</strong> <code>{command}</code></p>
                <pre>{output[:2000]}</pre>
                <a href="/whois">← Back</a>
            </div>
        </body>
        </html>
        '''

    except Exception as e:
        return f'<h1>Error:</h1><p>{str(e)}</p><a href="/whois">Back</a>', 500


@app.route('/about')
def about():
    """Informações sobre o lab"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About - Command Injection Lab</title>
        <style>
            body { font-family: Arial; padding: 40px; max-width: 900px; margin: 0 auto; }
            h1 { color: #667eea; }
            .section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
            pre { background: #2d2d2d; color: #0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
            code { background: #f5f5f5; padding: 2px 8px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>ℹ️ About - Basic Command Injection Lab</h1>

        <div class="section">
            <h2>🎯 Objetivos</h2>
            <ul>
                <li>Executar comandos básicos (whoami, id, ls)</li>
                <li>Ler arquivos sensíveis (/etc/passwd)</li>
                <li>Capturar flags em /tmp/flag.txt</li>
                <li>Explorar múltiplos injection points</li>
            </ul>
        </div>

        <div class="section">
            <h2>🚩 Flags</h2>
            <ul>
                <li><code>FLAG{basic_command_injection_success}</code> - em /tmp/flag.txt</li>
                <li>Credenciais em /tmp/config.conf</li>
            </ul>
        </div>

        <div class="section">
            <h2>💡 Payloads de Exemplo</h2>
            <pre>
# Separadores básicos
8.8.8.8; whoami
8.8.8.8 && id
8.8.8.8 || cat /etc/passwd
8.8.8.8 | cat /tmp/flag.txt

# Newline
8.8.8.8%0Awhoami

# Múltiplos comandos
8.8.8.8; whoami; id; ls -la

# Ler arquivos
8.8.8.8; cat /tmp/flag.txt
8.8.8.8; cat /etc/passwd
8.8.8.8; cat /tmp/config.conf

# Informações do sistema
8.8.8.8; uname -a
8.8.8.8; hostname
8.8.8.8; ps aux
            </pre>
        </div>

        <div class="section">
            <h2>🔍 Endpoints Vulneráveis</h2>
            <ul>
                <li><code>/ping</code> - ping -c 4 [IP]</li>
                <li><code>/traceroute/run</code> - traceroute [HOST]</li>
                <li><code>/nslookup/run</code> - nslookup [DOMAIN]</li>
                <li><code>/whois/run</code> - whois [DOMAIN]</li>
            </ul>
        </div>

        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("=" * 80)
    print("COMMAND INJECTION - BASIC LEVEL LAB")
    print("=" * 80)
    print("\n🌐 Aplicação: Network Utility Tools")
    print("\n🎯 Objetivos:")
    print("  1. Executar comandos via command injection")
    print("  2. Ler arquivos sensíveis")
    print("  3. Capturar flags em /tmp/")
    print("  4. Explorar múltiplos endpoints")
    print("\n🚩 Flags:")
    print("  - FLAG{basic_command_injection_success}")
    print("  - Credenciais em /tmp/config.conf")
    print("\n💡 Dicas:")
    print("  - Nenhum filtro implementado!")
    print("  - Teste separadores: ; && || |")
    print("  - 4 endpoints vulneráveis")
    print("\n💉 Exemplo de payload:")
    print("  8.8.8.8; whoami")
    print("  8.8.8.8 && cat /tmp/flag.txt")
    print("\n" + "=" * 80)

    init_flags()

    print("\n[+] Servidor rodando em http://localhost:5050")
    print("[*] Pressione Ctrl+C para parar\n")

    app.run(host='0.0.0.0', port=5050, debug=True)
