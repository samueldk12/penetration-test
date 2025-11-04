#!/usr/bin/env python3
"""
APLICAÇÃO VULNERÁVEL - NÍVEL MÉDIO
⚠️ APENAS PARA FINS EDUCACIONAIS
⚠️ NÃO USE EM PRODUÇÃO
⚠️ CONTÉM VULNERABILIDADES MAIS COMPLEXAS

Esta aplicação contém vulnerabilidades de nível médio:
- SQL Injection com bypass de filtros
- XSS com bypass de sanitização
- CSRF
- SSRF
- Command Injection
- Insecure Deserialization
"""

from flask import Flask, request, render_template_string, redirect, session, make_response
import sqlite3
import os
import subprocess
import pickle
import base64
import requests
from urllib.parse import urlparse
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    conn = sqlite3.connect('vulnerable_medium.db')
    c = conn.cursor()

    c.execute('''DROP TABLE IF EXISTS users''')
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                  email TEXT, role TEXT, api_key TEXT)''')

    # Senhas com hash MD5 (fraco)
    users = [
        ('admin', hashlib.md5(b'P@ssw0rd!').hexdigest(), 'admin@corp.com', 'admin', 'adm_key_123'),
        ('developer', hashlib.md5(b'dev123456').hexdigest(), 'dev@corp.com', 'dev', 'dev_key_456'),
        ('john', hashlib.md5(b'john2024').hexdigest(), 'john@corp.com', 'user', 'usr_key_789')
    ]

    for user in users:
        c.execute("INSERT INTO users (username, password, email, role, api_key) VALUES (?, ?, ?, ?, ?)", user)

    c.execute('''DROP TABLE IF EXISTS posts''')
    c.execute('''CREATE TABLE posts
                 (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT)''')

    c.execute("INSERT INTO posts (user_id, title, content) VALUES (1, 'Secret Project', 'FLAG{sql_injection_medium}')")

    conn.commit()
    conn.close()

HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Corporate Portal - Medium</title>
    <style>
        body { font-family: Arial; max-width: 1000px; margin: 50px auto; }
        .container { background: #f8f9fa; padding: 30px; border-radius: 10px; }
        input, textarea, button { margin: 10px 0; padding: 12px; width: 100%; }
        .warning { background: #ff6b6b; color: white; padding: 15px; border-radius: 5px; }
        .nav { background: #4CAF50; padding: 15px; margin-bottom: 20px; }
        .nav a { color: white; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/login">Login</a>
        <a href="/search">Search</a>
        <a href="/api">API</a>
        <a href="/tools">Tools</a>
    </div>
    <div class="container">
        <h1>🏢 Corporate Portal - Medium Security</h1>
        <div class="warning">
            <strong>⚠️ Sistema de Treinamento de Segurança</strong><br>
            Contém vulnerabilidades intencionais para educação
        </div>
        {{ content | safe }}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
    <h2>Bem-vindo ao Portal</h2>
    <p>Use as opções do menu acima para navegar.</p>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABILIDADE 1: SQL Injection com bypass de filtros simples
        # Filtro fraco que pode ser bypassado
        blacklist = ['or', 'OR', 'and', 'AND', '--', '#']

        # Tenta filtrar mas é bypassável com técnicas:
        # - Case variation: Or, oR
        # - Comentários: /**/
        # - Encoding: union select
        for bad in blacklist:
            if bad in username or bad in password:
                return "Caracteres suspeitos detectados!"

        conn = sqlite3.connect('vulnerable_medium.db')
        c = conn.cursor()

        # Hash MD5 da senha
        pwd_hash = hashlib.md5(password.encode()).hexdigest()

        # Ainda vulnerável a SQLi apesar do filtro
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{pwd_hash}'"

        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()

            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                return redirect('/dashboard')
            else:
                return "Login failed!"
        except Exception as e:
            return f"Error: {e}"

    content = """
    <h2>🔐 Login</h2>
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <p><small>Hint: SQL injection com bypass de filtros</small></p>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('vulnerable_medium.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM posts WHERE user_id = {session['user_id']}")
    posts = c.fetchall()
    conn.close()

    content = f"""
    <h2>📊 Dashboard - {session.get('username')}</h2>
    <h3>Your Posts:</h3>
    {"".join([f"<div><strong>{p[2]}</strong>: {p[3]}</div>" for p in posts])}
    <a href="/logout">Logout</a>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABILIDADE 2: XSS com bypass de sanitização fraca
    # Tenta sanitizar mas é bypassável
    sanitized = query.replace('<script>', '').replace('</script>', '')
    sanitized = sanitized.replace('onerror', '').replace('onclick', '')

    # Ainda vulnerável a: <scr<script>ipt>, <img src=x onerror=alert(1)>
    content = f"""
    <h2>🔍 Search Results</h2>
    <p>Results for: {sanitized}</p>
    <p><small>Hint: Bypass com nested tags ou event handlers</small></p>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/api/fetch', methods=['POST'])
def api_fetch():
    # VULNERABILIDADE 3: SSRF (Server-Side Request Forgery)
    url = request.form.get('url', '')

    # Tenta bloquear localhost mas é bypassável
    if 'localhost' in url.lower() or '127.0.0.1' in url:
        return "Localhost não permitido!"

    # Bypassável com: 127.1, 0.0.0.0, http://localtest.me
    try:
        response = requests.get(url, timeout=5)
        return f"<h2>Fetched:</h2><pre>{response.text[:500]}</pre>"
    except Exception as e:
        return f"Error: {e}"

@app.route('/tools', methods=['GET', 'POST'])
def tools():
    if request.method == 'POST':
        # VULNERABILIDADE 4: Command Injection
        command = request.form.get('command', '')

        # Filtro fraco
        if ';' in command or '|' in command or '&' in command:
            return "Caracteres proibidos!"

        # Bypassável com: $(command), `command`, newline
        try:
            result = subprocess.check_output(command, shell=True, timeout=5)
            return f"<pre>{result.decode()}</pre>"
        except Exception as e:
            return f"Error: {e}"

    content = """
    <h2>🛠️ System Tools</h2>
    <form method="POST">
        <input name="command" placeholder="Command (ex: whoami)">
        <button>Execute</button>
    </form>
    <p><small>Hint: Command injection com bypass</small></p>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/api/data', methods=['POST'])
def api_data():
    # VULNERABILIDADE 5: Insecure Deserialization
    data = request.form.get('data', '')

    try:
        # Desserializa dados pickle (MUITO PERIGOSO)
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return f"Deserialized: {obj}"
    except Exception as e:
        return f"Error: {e}"

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    # VULNERABILIDADE 6: CSRF (Cross-Site Request Forgery)
    # Sem token CSRF
    if request.method == 'POST':
        if 'user_id' not in session:
            return "Not logged in"

        amount = request.form.get('amount', '0')
        to_user = request.form.get('to_user', '')

        return f"""
        <h2>✅ Transfer Successful!</h2>
        <p>Transferred ${amount} to {to_user}</p>
        <p>FLAG: FLAG{{csrf_medium}}</p>
        """

    content = """
    <h2>💸 Transfer Money</h2>
    <form method="POST">
        <input name="to_user" placeholder="To User">
        <input name="amount" placeholder="Amount" type="number">
        <button>Transfer</button>
    </form>
    <p><small>Hint: Sem proteção CSRF</small></p>
    """
    return render_template_string(HOME_TEMPLATE, content=content)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    print("=" * 80)
    print("🎯 VULNERABLE WEB APP - MEDIUM LEVEL")
    print("=" * 80)
    print("⚠️  APENAS PARA FINS EDUCACIONAIS")
    print("=" * 80)
    print("\n🔍 Vulnerabilidades (com filtros bypassáveis):")
    print("  1. SQL Injection com bypass de filtro")
    print("  2. XSS com bypass de sanitização")
    print("  3. SSRF com bypass de blacklist")
    print("  4. Command Injection com bypass")
    print("  5. Insecure Deserialization (pickle)")
    print("  6. CSRF sem token")
    print("\n🚀 Servidor em http://localhost:5001")
    print("=" * 80)

    app.run(debug=True, host='0.0.0.0', port=5001)
