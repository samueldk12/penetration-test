#!/usr/bin/env python3
"""
SQL Injection - Basic Level
============================

Aplicação: Sistema de Login Simples
Porta: 5010
Dificuldade: 🟢 Básico (10 pontos)

Vulnerabilidades:
- SQLi direto no login (authentication bypass)
- Error-based SQL injection
- UNION-based data extraction
- Sem filtros ou proteções

Objetivo:
1. Fazer login como admin sem saber a senha
2. Extrair todos os usuários do banco
3. Descobrir a estrutura do banco (tabelas, colunas)

Dica: Comece testando aspas simples (') no campo username
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'basic-sqli-lab-key'

# Database setup
DB_PATH = '/tmp/basic_sqli.db'

def init_db():
    """Inicializa banco de dados"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabela de usuários
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabela secreta (para descobrir)
    c.execute('''
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            secret_key TEXT
        )
    ''')

    # Inserir dados
    users = [
        ('admin', 'Sup3rS3cr3tP@ss!', 'admin@company.com', 'admin'),
        ('john', 'john123', 'john@company.com', 'user'),
        ('mary', 'mary456', 'mary@company.com', 'user'),
        ('guest', 'guest', 'guest@company.com', 'guest'),
    ]

    for username, password, email, role in users:
        c.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                  (username, password, email, role))

    # Segredos
    secrets = [
        ('Database Password', 'db_prod_pass: MyPr0dP@ssw0rd123!', 'FLAG{basic_sqli_found}'),
        ('API Key', 'api_key: sk-1234567890abcdef', 'FLAG{union_based_sqli}'),
        ('Admin Token', 'admin_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', 'FLAG{error_based_sqli}'),
    ]

    for title, content, key in secrets:
        c.execute('INSERT INTO secrets (title, content, secret_key) VALUES (?, ?, ?)',
                  (title, content, key))

    conn.commit()
    conn.close()
    print("[+] Database initialized with test data")


@app.route('/')
def index():
    """Página inicial com formulário de login"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Basic SQL Injection Lab - Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 400px;
            }
            h1 {
                color: #667eea;
                text-align: center;
                margin-bottom: 30px;
            }
            .badge {
                background: #4caf50;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 12px;
                float: right;
            }
            input {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 2px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
                font-size: 14px;
            }
            button {
                width: 100%;
                padding: 12px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 10px;
            }
            button:hover {
                background: #5568d3;
            }
            .info {
                background: #e3f2fd;
                padding: 15px;
                border-radius: 5px;
                margin-top: 20px;
                font-size: 12px;
            }
            .hint {
                background: #fff3cd;
                padding: 10px;
                border-radius: 5px;
                margin-top: 10px;
                font-size: 12px;
            }
            a {
                color: #667eea;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Company Portal <span class="badge">BASIC</span></h1>

            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>

            <div class="info">
                <strong>🎯 Objetivo:</strong><br>
                1. Fazer login como admin sem saber a senha<br>
                2. Extrair todos os usuários do banco<br>
                3. Descobrir tabelas e dados secretos
            </div>

            <div class="hint">
                <strong>💡 Dica:</strong> Tente adicionar uma aspa simples (') no campo username
            </div>

            <div style="margin-top: 20px; text-align: center;">
                <a href="/search">🔍 Search Users</a> |
                <a href="/stats">📊 Statistics</a> |
                <a href="/about">ℹ️ About</a>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)


@app.route('/login', methods=['POST'])
def login():
    """
    VULNERÁVEL: SQL Injection no login
    Não usa prepared statements
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # VULNERÁVEL ❌ - String concatenation direta
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    print(f"[DEBUG] Query executada: {query}")

    try:
        c.execute(query)
        result = c.fetchone()

        if result:
            user_id, username, password, email, role, created_at = result
            html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Successful</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #4caf50 0%, #45a049 100%);
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }}
                    .container {{
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                        width: 500px;
                    }}
                    h1 {{ color: #4caf50; }}
                    .user-info {{
                        background: #f5f5f5;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .flag {{
                        background: #ffd700;
                        padding: 10px;
                        border-radius: 5px;
                        margin: 10px 0;
                        font-weight: bold;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Login Successful!</h1>
                    <div class="user-info">
                        <strong>User ID:</strong> {user_id}<br>
                        <strong>Username:</strong> {username}<br>
                        <strong>Email:</strong> {email}<br>
                        <strong>Role:</strong> {role}<br>
                        <strong>Created:</strong> {created_at}
                    </div>
                    {'<div class="flag">🚩 FLAG{basic_sqli_auth_bypass}</div>' if role == 'admin' else ''}
                    <p><a href="/">← Back to login</a></p>
                </div>
            </body>
            </html>
            '''
            return render_template_string(html)
        else:
            return render_template_string('''
                <h1>❌ Login Failed</h1>
                <p>Invalid credentials</p>
                <p><a href="/">← Try again</a></p>
            ''')

    except sqlite3.Error as e:
        # VULNERÁVEL ❌ - Mostra erro SQL completo
        conn.close()
        return render_template_string(f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Database Error</title>
                <style>
                    body {{ font-family: monospace; padding: 20px; }}
                    .error {{ background: #ffebee; padding: 20px; border-left: 5px solid #f44336; }}
                    code {{ background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }}
                </style>
            </head>
            <body>
                <h1>⚠️ Database Error</h1>
                <div class="error">
                    <strong>SQL Error:</strong><br>
                    <code>{str(e)}</code><br><br>
                    <strong>Query:</strong><br>
                    <code>{query}</code>
                </div>
                <p><strong>💡 Dica:</strong> Mensagens de erro SQL podem revelar a estrutura do banco!</p>
                <p><a href="/">← Back</a></p>
            </body>
            </html>
        '''), 500

    finally:
        conn.close()


@app.route('/search')
def search():
    """
    VULNERÁVEL: SQL Injection em search
    """
    query_param = request.args.get('q', '')

    html_form = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Search</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            input { padding: 10px; width: 300px; margin: 10px 0; }
            button { padding: 10px 20px; background: #667eea; color: white; border: none; cursor: pointer; }
            .result { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>🔍 User Search</h1>
        <form method="GET" action="/search">
            <input type="text" name="q" placeholder="Search username..." value="''' + query_param + '''">
            <button type="submit">Search</button>
        </form>
        <p><a href="/">← Back</a></p>
    '''

    if query_param:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # VULNERÁVEL ❌
        query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{query_param}%'"

        print(f"[DEBUG] Search query: {query}")

        try:
            c.execute(query)
            results = c.fetchall()

            html_form += '<h2>Results:</h2>'

            if results:
                for row in results:
                    html_form += f'''
                    <div class="result">
                        <strong>ID:</strong> {row[0]} |
                        <strong>Username:</strong> {row[1]} |
                        <strong>Email:</strong> {row[2]} |
                        <strong>Role:</strong> {row[3]}
                    </div>
                    '''
            else:
                html_form += '<p>No results found.</p>'

        except sqlite3.Error as e:
            html_form += f'<div style="background: #ffebee; padding: 10px;"><strong>SQL Error:</strong> {str(e)}</div>'

        finally:
            conn.close()

    html_form += '</body></html>'
    return render_template_string(html_form)


@app.route('/stats')
def stats():
    """
    VULNERÁVEL: SQL Injection em ORDER BY
    """
    order_by = request.args.get('order', 'id')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # VULNERÁVEL ❌ - ORDER BY injection
    query = f"SELECT id, username, role, created_at FROM users ORDER BY {order_by}"

    print(f"[DEBUG] Stats query: {query}")

    html = '''
    <html>
    <head>
        <title>User Statistics</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #667eea; color: white; }
            a { color: #667eea; margin: 0 10px; }
        </style>
    </head>
    <body>
        <h1>📊 User Statistics</h1>
        <p>
            <strong>Order by:</strong>
            <a href="?order=id">ID</a> |
            <a href="?order=username">Username</a> |
            <a href="?order=role">Role</a> |
            <a href="?order=created_at">Date</a>
        </p>
    '''

    try:
        c.execute(query)
        results = c.fetchall()

        html += '<table><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th></tr>'

        for row in results:
            html += f'<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>'

        html += '</table>'

    except sqlite3.Error as e:
        html += f'<div style="background: #ffebee; padding: 10px;"><strong>Error:</strong> {str(e)}</div>'

    finally:
        conn.close()

    html += '<p><a href="/">← Back</a></p></body></html>'
    return render_template_string(html)


@app.route('/about')
def about():
    """Informações sobre o lab"""
    return '''
    <html>
    <head>
        <title>About</title>
        <style>
            body { font-family: Arial; padding: 40px; max-width: 800px; margin: 0 auto; }
            h1 { color: #667eea; }
            .info { background: #e3f2fd; padding: 20px; border-radius: 5px; margin: 20px 0; }
            pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>ℹ️ About This Lab</h1>

        <div class="info">
            <h2>🎯 Objetivos</h2>
            <ul>
                <li>Aprender SQL Injection básico</li>
                <li>Praticar authentication bypass</li>
                <li>Extrair dados com UNION SELECT</li>
                <li>Descobrir estrutura do banco</li>
            </ul>
        </div>

        <div class="info">
            <h2>🚩 Flags Disponíveis</h2>
            <ul>
                <li><code>FLAG{basic_sqli_auth_bypass}</code> - Login como admin</li>
                <li><code>FLAG{error_based_sqli}</code> - Usar erro para descobrir estrutura</li>
                <li><code>FLAG{union_based_sqli}</code> - Extrair dados com UNION</li>
                <li><code>FLAG{basic_sqli_found}</code> - Encontrar tabela secrets</li>
            </ul>
        </div>

        <div class="info">
            <h2>💡 Dicas</h2>
            <ol>
                <li>Comece testando aspas simples (') para gerar erros</li>
                <li>Use <code>--</code> ou <code>#</code> para comentar resto da query</li>
                <li>Tente bypass: <code>admin' OR '1'='1'--</code></li>
                <li>Use UNION para extrair dados: <code>' UNION SELECT ...</code></li>
                <li>Descubra tabelas: <code>' UNION SELECT name FROM sqlite_master WHERE type='table'--</code></li>
            </ol>
        </div>

        <div class="info">
            <h2>📚 Recursos</h2>
            <ul>
                <li><a href="/">Login Page</a></li>
                <li><a href="/search">User Search</a></li>
                <li><a href="/stats">Statistics</a></li>
            </ul>
        </div>

        <div class="info">
            <h2>🔧 Payloads de Exemplo</h2>
            <pre>
# Authentication Bypass
admin' OR '1'='1'--
admin'--
' OR 1=1--

# UNION-based Extraction
' UNION SELECT 1,2,3,4,5,6--
' UNION SELECT id, username, password, email, role, created_at FROM users--
' UNION SELECT 1, name, sql, 4, 5, 6 FROM sqlite_master WHERE type='table'--

# Error-based
' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS INTEGER)--
            </pre>
        </div>

        <p><a href="/">← Back to Login</a></p>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("=" * 80)
    print("SQL INJECTION - BASIC LEVEL LAB")
    print("=" * 80)
    print("\n🎯 Objetivos:")
    print("  1. Login como admin (bypass authentication)")
    print("  2. Extrair todos os usuários do banco")
    print("  3. Descobrir tabela 'secrets' e seu conteúdo")
    print("\n🚩 Flags:")
    print("  - FLAG{basic_sqli_auth_bypass}")
    print("  - FLAG{error_based_sqli}")
    print("  - FLAG{union_based_sqli}")
    print("  - FLAG{basic_sqli_found}")
    print("\n💡 Dicas:")
    print("  - Teste aspas simples (') para gerar erros")
    print("  - Use comentários (-- ou #) para ignorar resto da query")
    print("  - Tente: admin' OR '1'='1'--")
    print("\n" + "=" * 80)
    print("\n[*] Inicializando banco de dados...")

    init_db()

    print("[+] Servidor rodando em http://localhost:5010")
    print("[*] Pressione Ctrl+C para parar\n")

    app.run(host='0.0.0.0', port=5010, debug=True)
