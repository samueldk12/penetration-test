#!/usr/bin/env python3
"""
APLICAÇÃO VULNERÁVEL - NÍVEL DIFÍCIL
⚠️ APENAS PARA FINS EDUCACIONAIS
⚠️ NÃO USE EM PRODUÇÃO
⚠️ VULNERABILIDADES COMPLEXAS E SOFISTICADAS

Esta aplicação contém vulnerabilidades avançadas:
- Blind SQL Injection com WAF bypass
- Polyglot XSS
- Second-Order SQL Injection
- Race Condition
- JWT vulnerabilities
- Advanced SSRF com bypass DNS
- Type Confusion
"""

from flask import Flask, request, render_template_string, redirect, session, jsonify
import sqlite3
import os
import jwt
import time
import hashlib
import re
import requests
from functools import wraps
import threading

app = Flask(__name__)
app.secret_key = 'super_secret_jwt_key_complex_2024'

# Rate limiting storage
rate_limit_storage = {}
rate_limit_lock = threading.Lock()

def init_db():
    conn = sqlite3.connect('vulnerable_hard.db')
    c = conn.cursor()

    c.execute('''DROP TABLE IF EXISTS users''')
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                  email TEXT, role TEXT, balance INTEGER, api_token TEXT)''')

    # Senhas com bcrypt (mas vulnerável a outras coisas)
    import hashlib
    users = [
        ('administrator', hashlib.sha256(b'C0mpl3x_P@ssw0rd!2024').hexdigest(),
         'admin@enterprise.com', 'superadmin', 10000, 'adm_token_xyz'),
        ('manager', hashlib.sha256(b'Manag3r#2024').hexdigest(),
         'manager@enterprise.com', 'manager', 5000, 'mgr_token_abc'),
        ('user_johndoe', hashlib.sha256(b'Johnd0e!Pass').hexdigest(),
         'john@enterprise.com', 'user', 1000, 'usr_token_def')
    ]

    for user in users:
        c.execute("INSERT INTO users (username, password, email, role, balance, api_token) VALUES (?, ?, ?, ?, ?, ?)", user)

    c.execute('''DROP TABLE IF EXISTS messages''')
    c.execute('''CREATE TABLE messages
                 (id INTEGER PRIMARY KEY, from_user INTEGER, to_user INTEGER,
                  subject TEXT, body TEXT, read INTEGER DEFAULT 0)''')

    c.execute("INSERT INTO messages (from_user, to_user, subject, body) VALUES (1, 2, 'Secret', 'FLAG{blind_sqli_hard}')")

    c.execute('''DROP TABLE IF EXISTS logs''')
    c.execute('''CREATE TABLE logs
                 (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp INTEGER)''')

    conn.commit()
    conn.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'error': 'Missing token'}), 401

        try:
            # VULNERABILIDADE 1: JWT com algorithm confusion
            # Aceita 'none' algorithm se payload especificar
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256', 'none'])
            request.user = payload
            return f(*args, **kwargs)
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    return decorated

def waf_check(value):
    """
    WAF (Web Application Firewall) simulado
    Tenta bloquear ataques mas pode ser bypassado
    """
    # Regex patterns comuns de WAF
    patterns = [
        r'(\bor\b|\band\b)',  # OR/AND
        r'(union.*select)',   # UNION SELECT
        r'(<script[^>]*>)',   # <script>
        r'(javascript:)',     # javascript:
        r'(onerror|onclick)', # Event handlers
        r'(\.\./)',           # Path traversal
        r'(;|\||&)',          # Command injection
    ]

    value_lower = value.lower()

    for pattern in patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return False

    return True

HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Security Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(255,255,255,0.95); padding: 20px;
                  border-radius: 10px; margin-bottom: 20px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .content { background: white; padding: 30px; border-radius: 10px;
                   box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        input, textarea { width: 100%; padding: 12px; margin: 10px 0;
                         border: 2px solid #ddd; border-radius: 5px; }
        button { background: #667eea; color: white; padding: 12px 30px;
                border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #764ba2; }
        .warning { background: #ff6b6b; color: white; padding: 15px;
                  border-radius: 5px; margin: 20px 0; }
        .nav { display: flex; gap: 20px; }
        .nav a { color: #667eea; text-decoration: none; font-weight: bold; }
        .flag { background: #ffd93d; padding: 10px; border-radius: 5px;
               font-family: monospace; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Enterprise Security Platform</h1>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/api/docs">API Docs</a>
                <a href="/admin">Admin</a>
            </div>
        </div>
        <div class="content">
            <div class="warning">
                <strong>⚠️ ADVANCED SECURITY TRAINING SYSTEM</strong><br>
                Vulnerabilidades complexas para profissionais de segurança
            </div>
            {{ content | safe }}
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
    <h2>🎯 Desafios Avançados de Segurança</h2>
    <p>Esta aplicação contém vulnerabilidades sofisticadas que requerem técnicas avançadas.</p>

    <h3>📚 Endpoints Disponíveis:</h3>
    <ul>
        <li><code>POST /api/login</code> - Autenticação JWT</li>
        <li><code>GET /api/users/search</code> - Busca (Blind SQLi)</li>
        <li><code>POST /api/profile/update</code> - Atualizar perfil (Second-Order SQLi)</li>
        <li><code>POST /api/transfer</code> - Transferência (Race Condition)</li>
        <li><code>POST /api/webhook</code> - Webhook (SSRF Avançado)</li>
        <li><code>GET /render</code> - Render template (SSTI)</li>
    </ul>

    <h3>🔐 Credenciais de Teste:</h3>
    <pre>
    administrator:C0mpl3x_P@ssw0rd!2024
    manager:Manag3r#2024
    user_johndoe:Johnd0e!Pass
    </pre>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # Hash da senha
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('vulnerable_hard.db')
    c = conn.cursor()

    # Usa prepared statement (seguro contra SQLi simples)
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, pwd_hash))
    user = c.fetchone()
    conn.close()

    if user:
        # Cria JWT token
        token_payload = {
            'user_id': user[0],
            'username': user[1],
            'role': user[4],
            'exp': int(time.time()) + 3600
        }

        token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')

        return jsonify({
            'success': True,
            'token': token,
            'message': 'Login successful'
        })

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/users/search')
@require_auth
def api_search():
    """
    VULNERABILIDADE 2: Blind SQL Injection com bypass de WAF

    A aplicação usa WAF mas é bypassável com:
    - URL encoding duplo
    - Case variation avançada
    - Comentários inline
    - Time-based blind SQLi
    """
    query = request.args.get('q', '')

    # WAF check (bypassável)
    if not waf_check(query):
        return jsonify({'error': 'Suspicious input detected by WAF'}), 400

    conn = sqlite3.connect('vulnerable_hard.db')
    c = conn.cursor()

    # Vulnerable query (mesmo com WAF)
    # Bypassável com: q=' oR(1=1)--
    # Ou time-based: q=' AND(SELECT*FROM(SELECT(SLEEP(5)))a)--
    sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"

    try:
        c.execute(sql)
        users = c.fetchall()
        conn.close()

        return jsonify({
            'results': [{'username': u[0], 'email': u[1]} for u in users]
        })
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/profile/update', methods=['POST'])
@require_auth
def update_profile():
    """
    VULNERABILIDADE 3: Second-Order SQL Injection

    O input é sanitizado na inserção, mas usado sem sanitização
    em queries subsequentes
    """
    data = request.get_json()
    new_email = data.get('email', '')
    user_id = request.user['user_id']

    # Primeira query: sanitizada (prepared statement)
    conn = sqlite3.connect('vulnerable_hard.db')
    c = conn.cursor()
    c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    conn.commit()

    # Log da ação
    c.execute("INSERT INTO logs (user_id, action, timestamp) VALUES (?, ?, ?)",
              (user_id, f"Email updated to {new_email}", int(time.time())))
    conn.commit()

    # Segunda query: usa o email armazenado SEM sanitização
    # Se o email contiver SQL, será executado aqui
    c.execute(f"SELECT * FROM users WHERE email = '{new_email}'")
    user = c.fetchone()
    conn.close()

    return jsonify({'success': True, 'message': 'Profile updated'})

@app.route('/api/transfer', methods=['POST'])
@require_auth
def transfer():
    """
    VULNERABILIDADE 4: Race Condition

    Permite transferir mais dinheiro do que disponível
    se requisições simultâneas forem enviadas
    """
    data = request.get_json()
    amount = int(data.get('amount', 0))
    to_user = data.get('to_user', '')

    user_id = request.user['user_id']

    conn = sqlite3.connect('vulnerable_hard.db')
    c = conn.cursor()

    # Check balance (vulnerable to race condition)
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = c.fetchone()[0]

    if balance >= amount:
        # Pequeno delay que permite race condition
        time.sleep(0.1)

        # Deduz do remetente
        c.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))

        # Adiciona ao destinatário
        c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to_user))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Transferred ${amount} to {to_user}',
            'flag': 'FLAG{race_condition_hard}'
        })

    conn.close()
    return jsonify({'error': 'Insufficient balance'}), 400

@app.route('/api/webhook', methods=['POST'])
@require_auth
def webhook():
    """
    VULNERABILIDADE 5: SSRF Avançado com bypass de proteções

    Implementa múltiplas proteções mas todas são bypassáveis
    """
    data = request.get_json()
    url = data.get('url', '')

    # Proteção 1: Blacklist de hostnames (bypassável)
    blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', 'metadata']

    parsed = urlparse(url)
    if any(blocked in parsed.netloc.lower() for blocked in blocked_hosts):
        return jsonify({'error': 'Blocked host'}), 400

    # Proteção 2: Apenas HTTP/HTTPS (bypassável com redirect)
    if parsed.scheme not in ['http', 'https']:
        return jsonify({'error': 'Invalid protocol'}), 400

    # Proteção 3: Sem IPs privados (bypassável com DNS rebinding)
    # Bypassável com: http://127.1, http://[::1], http://localtest.me

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)

        return jsonify({
            'success': True,
            'content': response.text[:500],
            'flag': 'FLAG{ssrf_advanced_hard}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/render')
def render():
    """
    VULNERABILIDADE 6: Server-Side Template Injection (SSTI)

    Usa template engine de forma insegura
    """
    template = request.args.get('template', 'Hello {{ name }}!')
    name = request.args.get('name', 'Guest')

    # SSTI vulnerability
    # Payload: {{config.items()}} ou {{''.__class__.__mro__[1].__subclasses__()}}
    try:
        result = render_template_string(template, name=name)
        return result
    except Exception as e:
        return f"Error: {e}"

@app.route('/admin/export')
@require_auth
def admin_export():
    """
    VULNERABILIDADE 7: XML External Entity (XXE)

    Processa XML de forma insegura
    """
    xml_data = request.args.get('data', '')

    # Processa XML sem desabilitar entidades externas
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_data)

        return jsonify({
            'success': True,
            'data': ET.tostring(root).decode()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/docs')
def api_docs():
    content = """
    <h2>📖 API Documentation</h2>

    <h3>Authentication</h3>
    <pre>
POST /api/login
Content-Type: application/json

{
    "username": "user",
    "password": "pass"
}

Response: {"token": "JWT_TOKEN"}
    </pre>

    <h3>Search Users (Blind SQLi)</h3>
    <pre>
GET /api/users/search?q=admin
Authorization: Bearer JWT_TOKEN

Vulnerable to:
- Blind SQL Injection
- Time-based detection
- WAF bypass techniques
    </pre>

    <h3>Race Condition Demo</h3>
    <pre>
# Send multiple simultaneous requests:
POST /api/transfer
{
    "amount": 500,
    "to_user": "manager"
}
    </pre>

    <h3>SSRF Advanced</h3>
    <pre>
POST /api/webhook
{
    "url": "http://127.1/"
}

Bypassable with:
- DNS rebinding
- Decimal IP: http://2130706433/
- IPv6: http://[::1]/
- Redirects
    </pre>

    <h3>SSTI</h3>
    <pre>
GET /render?template={{config}}&name=test

Payloads:
- {{config.items()}}
- {{''.__class__.__mro__[1].__subclasses__()}}
- {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
    </pre>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

if __name__ == '__main__':
    init_db()
    print("=" * 80)
    print("🎯 VULNERABLE WEB APP - HARD LEVEL")
    print("=" * 80)
    print("⚠️  APENAS PARA FINS EDUCACIONAIS - ESPECIALISTAS")
    print("=" * 80)
    print("\n🔍 Vulnerabilidades Avançadas:")
    print("  1. JWT Algorithm Confusion")
    print("  2. Blind SQL Injection com WAF bypass")
    print("  3. Second-Order SQL Injection")
    print("  4. Race Condition em transferências")
    print("  5. SSRF Avançado com múltiplos bypasses")
    print("  6. Server-Side Template Injection (SSTI)")
    print("  7. XML External Entity (XXE)")
    print("\n💡 Técnicas Requeridas:")
    print("  - WAF bypass avançado")
    print("  - Blind SQLi time-based")
    print("  - Race condition exploitation")
    print("  - DNS rebinding")
    print("  - Template injection")
    print("\n🚀 Servidor em http://localhost:5002")
    print("=" * 80)

    app.run(debug=True, host='0.0.0.0', port=5002)
