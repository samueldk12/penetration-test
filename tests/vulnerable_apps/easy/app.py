#!/usr/bin/env python3
"""
APLICAÇÃO VULNERÁVEL - NÍVEL FÁCIL
⚠️ APENAS PARA FINS EDUCACIONAIS
⚠️ NÃO USE EM PRODUÇÃO
⚠️ CONTÉM VULNERABILIDADES INTENCIONAIS

Esta aplicação contém as seguintes vulnerabilidades fáceis de explorar:
- SQL Injection básica
- XSS Reflected simples
- Directory Listing
- Credenciais padrão
- Informações sensíveis expostas
"""

from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_123'  # Hardcoded secret key

# Cria banco de dados vulnerável
def init_db():
    conn = sqlite3.connect('vulnerable_easy.db')
    c = conn.cursor()

    # Cria tabela de usuários
    c.execute('''DROP TABLE IF EXISTS users''')
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')

    # Insere usuários vulneráveis
    users = [
        ('admin', 'admin', 'admin@example.com', 'admin'),
        ('user', 'password', 'user@example.com', 'user'),
        ('guest', 'guest', 'guest@example.com', 'guest')
    ]

    for user in users:
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", user)

    # Cria tabela de segredos
    c.execute('''DROP TABLE IF EXISTS secrets''')
    c.execute('''CREATE TABLE secrets
                 (id INTEGER PRIMARY KEY, user_id INTEGER, secret TEXT)''')

    c.execute("INSERT INTO secrets (user_id, secret) VALUES (1, 'FLAG{sql_injection_easy}')")
    c.execute("INSERT INTO secrets (user_id, secret) VALUES (2, 'User secret data')")

    conn.commit()
    conn.close()

# Template HTML simples
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App - Easy</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        input, button { margin: 10px 0; padding: 10px; }
        .warning { background: #ffcccc; padding: 10px; border-radius: 5px; margin: 20px 0; }
        .result { background: #ccffcc; padding: 10px; border-radius: 5px; margin: 20px 0; }
        a { color: #0066cc; text-decoration: none; margin: 0 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Vulnerable Web App - Easy Level</h1>
        <div class="warning">
            <strong>⚠️ AVISO:</strong> Esta aplicação contém vulnerabilidades intencionais para fins educacionais!
        </div>

        <h2>🔐 Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>

        <h2>🔍 Busca de Usuários</h2>
        <form method="GET" action="/search">
            <input type="text" name="q" placeholder="Nome do usuário"><br>
            <button type="submit">Buscar</button>
        </form>

        <h2>📝 Comentários</h2>
        <form method="POST" action="/comment">
            <input type="text" name="comment" placeholder="Seu comentário"><br>
            <button type="submit">Enviar</button>
        </form>

        <hr>
        <div>
            <a href="/debug">Debug Info</a> |
            <a href="/admin">Admin Panel</a> |
            <a href="/files">Files</a>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # VULNERABILIDADE 1: SQL Injection básica
    # Query vulnerável concatenando strings diretamente
    conn = sqlite3.connect('vulnerable_easy.db')
    c = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG] Query: {query}")  # Vaza query no log

    try:
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            return f"""
            <h1>✅ Login Successful!</h1>
            <p>Welcome, {user[1]}!</p>
            <p>Role: {user[4]}</p>
            <p>Email: {user[3]}</p>
            <a href="/">Back</a>
            """
        else:
            return "<h1>❌ Login Failed!</h1><a href='/'>Back</a>"
    except Exception as e:
        # VULNERABILIDADE 2: Mensagem de erro verbosa
        return f"<h1>Error:</h1><pre>{str(e)}</pre><a href='/'>Back</a>"

@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABILIDADE 3: XSS Reflected
    # Reflete input do usuário sem sanitização
    return f"""
    <h1>Resultados da busca</h1>
    <p>Você buscou por: {query}</p>
    <a href="/">Back</a>
    """

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form.get('comment', '')

    # VULNERABILIDADE 4: XSS Stored (simulado)
    # Armazena e exibe comentários sem sanitização
    return f"""
    <h1>Comentário enviado!</h1>
    <div style="border: 1px solid #ccc; padding: 10px; margin: 10px;">
        {comment}
    </div>
    <a href="/">Back</a>
    """

@app.route('/debug')
def debug():
    # VULNERABILIDADE 5: Information Disclosure
    # Expõe informações sensíveis
    return f"""
    <h1>🐛 Debug Information</h1>
    <pre>
    Secret Key: {app.secret_key}
    Session: {session}
    Environment Variables:
    {os.environ}

    Database Path: vulnerable_easy.db
    Default Credentials:
    - admin:admin
    - user:password
    - guest:guest

    FLAG: FLAG{{info_disclosure_easy}}
    </pre>
    <a href="/">Back</a>
    """

@app.route('/admin')
def admin():
    # VULNERABILIDADE 6: Missing Access Control
    # Sem verificação de autorização
    conn = sqlite3.connect('vulnerable_easy.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    c.execute("SELECT * FROM secrets")
    secrets = c.fetchall()
    conn.close()

    return f"""
    <h1>👑 Admin Panel</h1>
    <h2>All Users:</h2>
    <pre>{users}</pre>
    <h2>All Secrets:</h2>
    <pre>{secrets}</pre>
    <p>FLAG: FLAG{{broken_access_control_easy}}</p>
    <a href="/">Back</a>
    """

@app.route('/files')
def files():
    # VULNERABILIDADE 7: Directory Listing
    # Lista arquivos do servidor
    files = os.listdir('.')
    return f"""
    <h1>📁 Files</h1>
    <ul>
    {"".join([f"<li>{f}</li>" for f in files])}
    </ul>
    <a href="/">Back</a>
    """

@app.route('/file')
def read_file():
    # VULNERABILIDADE 8: Path Traversal básico
    filename = request.args.get('name', 'app.py')
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<h1>File: {filename}</h1><pre>{content}</pre>"
    except:
        return "File not found"

if __name__ == '__main__':
    init_db()
    print("=" * 80)
    print("🎯 VULNERABLE WEB APP - EASY LEVEL")
    print("=" * 80)
    print("⚠️  APENAS PARA FINS EDUCACIONAIS")
    print("⚠️  CONTÉM VULNERABILIDADES INTENCIONAIS")
    print("=" * 80)
    print("\n🔍 Vulnerabilidades incluídas:")
    print("  1. SQL Injection básica no login")
    print("  2. XSS Reflected na busca")
    print("  3. XSS Stored nos comentários")
    print("  4. Information Disclosure em /debug")
    print("  5. Broken Access Control em /admin")
    print("  6. Directory Listing em /files")
    print("  7. Path Traversal em /file")
    print("  8. Credenciais padrão (admin:admin)")
    print("\n🚀 Iniciando servidor em http://localhost:5000")
    print("=" * 80)

    app.run(debug=True, host='0.0.0.0', port=5000)
