#!/usr/bin/env python3
"""
🔐 Broken Access Control - Basic Lab
Laboratório de Vulnerabilidades de Controle de Acesso

Porta: 5030
Dificuldade: 🟢 Básico
Pontos: 10

VULNERABILIDADES:
1. IDOR em perfis de usuários
2. IDOR em mensagens privadas
3. Missing function level access control (admin panel)
4. Horizontal privilege escalation

FLAGS:
- FLAG{idor_profile_access} - Acesse perfil de outro usuário
- FLAG{idor_private_messages} - Leia mensagens de outro usuário
- FLAG{admin_panel_access} - Acesse painel admin sem ser admin
- FLAG{privilege_escalation} - Torne-se admin

USUÁRIOS DE TESTE:
- alice / password123 (user, ID=1)
- bob / password456 (user, ID=2)
- admin / admin123 (admin, ID=3)
"""

from flask import Flask, request, render_template_string, session, redirect, jsonify
import sqlite3
from functools import wraps
import hashlib
import json

app = Flask(__name__)
app.secret_key = 'access_control_secret_key'

# Banco de dados
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()

    # Tabela de usuários
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                  password TEXT, email TEXT, role TEXT, bio TEXT,
                  balance REAL)''')

    # Tabela de mensagens
    c.execute('''CREATE TABLE messages
                 (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER,
                  subject TEXT, content TEXT, created_at TEXT)''')

    # Tabela de documentos
    c.execute('''CREATE TABLE documents
                 (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT,
                  content TEXT, is_private INTEGER)''')

    # Usuários de teste
    users = [
        (1, 'alice', hashlib.md5(b'password123').hexdigest(), 'alice@example.com', 'user',
         'Desenvolvedora Python', 100.0),
        (2, 'bob', hashlib.md5(b'password456').hexdigest(), 'bob@example.com', 'user',
         'Analista de Segurança', 250.0),
        (3, 'admin', hashlib.md5(b'admin123').hexdigest(), 'admin@example.com', 'admin',
         'Administrador do Sistema', 999999.0),
        (4, 'charlie', hashlib.md5(b'charlie789').hexdigest(), 'charlie@example.com', 'user',
         'Pentester', 500.0),
    ]
    c.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)', users)

    # Mensagens de teste
    messages = [
        (1, 1, 2, 'Olá Bob!', 'Como vai? Vamos almoçar amanhã?', '2024-01-01 10:00:00'),
        (2, 2, 1, 'Re: Olá Bob!', 'Opa Alice! Vamos sim, meio-dia?', '2024-01-01 10:30:00'),
        (3, 3, 1, 'Confidencial', 'Alice, preciso que revise este código secreto: FLAG{idor_private_messages}', '2024-01-01 11:00:00'),
        (4, 3, 2, 'Admin Message', 'Bob, você foi promovido! Seus novos acessos estão prontos.', '2024-01-01 12:00:00'),
        (5, 4, 3, 'Vulnerability Report', 'Admin, encontrei várias falhas no sistema...', '2024-01-01 13:00:00'),
    ]
    c.executemany('INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?)', messages)

    # Documentos
    documents = [
        (1, 1, 'Meu Diário', 'Hoje foi um dia incrível!', 1),
        (2, 2, 'Relatório de Segurança', 'Vulnerabilidades encontradas...', 1),
        (3, 3, 'Senhas do Sistema', 'root:Tr0ub4dor&3\nadmin:P@ssw0rd123!', 1),
        (4, 1, 'Receita de Bolo', 'Ingredientes: farinha, ovos, açúcar...', 0),
    ]
    c.executemany('INSERT INTO documents VALUES (?, ?, ?, ?, ?)', documents)

    conn.commit()
    return conn

db = init_db()

def login_required(f):
    """Decorator para verificar se usuário está logado"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Access Control Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .user-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .feature-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            transition: transform 0.3s;
            cursor: pointer;
        }
        .feature-card:hover {
            transform: translateY(-5px);
        }
        .flag {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
        a {
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
        }
        .btn {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Social Network</h1>
        <p style="color: #666; margin-bottom: 20px;">Rede Social com Problemas de Controle de Acesso</p>

        <div class="user-info">
            <strong>👤 Logado como:</strong> {{ username }} ({{ role }}) |
            <strong>💰 Saldo:</strong> ${{ balance }} |
            <a href="/logout" class="btn">Sair</a>
        </div>

        <div class="feature-grid">
            <div class="feature-card" onclick="location.href='/profile/{{ user_id }}'">
                <h3>👤 Meu Perfil</h3>
                <p>Ver e editar perfil</p>
            </div>

            <div class="feature-card" onclick="location.href='/messages'">
                <h3>💬 Mensagens</h3>
                <p>Ver suas mensagens</p>
            </div>

            <div class="feature-card" onclick="location.href='/documents'">
                <h3>📄 Documentos</h3>
                <p>Gerenciar documentos</p>
            </div>

            <div class="feature-card" onclick="location.href='/users'">
                <h3>👥 Usuários</h3>
                <p>Lista de usuários</p>
            </div>

            {% if role == 'admin' %}
            <div class="feature-card" onclick="location.href='/admin'">
                <h3>⚙️ Admin Panel</h3>
                <p>Painel administrativo</p>
            </div>
            {% endif %}
        </div>

        <div class="flag">
            <h3>🚩 Objetivos</h3>
            <p>🎯 FLAG 1: Acesse o perfil de outro usuário (IDOR)</p>
            <p>🎯 FLAG 2: Leia mensagens privadas de outro usuário</p>
            <p>🎯 FLAG 3: Acesse o painel admin sem ser admin</p>
            <p>🎯 FLAG 4: Escale privilégios para se tornar admin</p>
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 10px;">
            <h3>💡 Dicas</h3>
            <p>• Observe os IDs nas URLs</p>
            <p>• Tente acessar /profile/1, /profile/2, /profile/3</p>
            <p>• Experimente acessar /admin diretamente</p>
            <p>• Use as ferramentas de desenvolvedor do navegador</p>
            <p>• Tente modificar parâmetros nas requisições</p>
        </div>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #667eea;
            margin-bottom: 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
        }
        button {
            width: 100%;
            padding: 15px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
        }
        button:hover { background: #5568d3; }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .users-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🔐 Login</h1>

        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}

        <form method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>

            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>

            <button type="submit">Entrar</button>
        </form>

        <div class="users-info">
            <strong>👥 Usuários de Teste:</strong><br>
            • alice / password123<br>
            • bob / password456<br>
            • admin / admin123<br>
            • charlie / charlie789
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
@login_required
def index():
    """Página inicial"""
    user_id = session['user_id']
    c = db.cursor()
    c.execute('SELECT username, role, balance FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    return render_template_string(HOME_TEMPLATE,
                                  user_id=user_id,
                                  username=user[0],
                                  role=user[1],
                                  balance=user[2])

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login"""
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)

    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = hashlib.md5(password.encode()).hexdigest()

    c = db.cursor()
    c.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?',
              (username, password_hash))
    user = c.fetchone()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[2]
        return redirect('/')
    else:
        return render_template_string(LOGIN_TEMPLATE, error='Credenciais inválidas')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect('/login')

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    """
    VULNERÁVEL: IDOR
    Permite acessar perfil de qualquer usuário
    """
    c = db.cursor()
    c.execute('SELECT id, username, email, role, bio, balance FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    if not user:
        return 'Usuário não encontrado', 404

    # VULNERÁVEL ❌ - Não verifica se é o próprio usuário!
    flag_message = ''
    if user_id != session['user_id']:
        flag_message = '<div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0;">🚩 FLAG{idor_profile_access} - Você acessou o perfil de outro usuário!</div>'

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>👤 Perfil de {user[1]}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 800px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }}
            h1 {{ color: #667eea; margin-bottom: 20px; }}
            .profile-info {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }}
            .info-row {{
                padding: 10px 0;
                border-bottom: 1px solid #ddd;
            }}
            .back-link {{
                display: inline-block;
                margin-bottom: 20px;
                color: #667eea;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← Voltar</a>
            <h1>👤 Perfil de {user[1]}</h1>

            {flag_message}

            <div class="profile-info">
                <div class="info-row"><strong>ID:</strong> {user[0]}</div>
                <div class="info-row"><strong>Username:</strong> {user[1]}</div>
                <div class="info-row"><strong>Email:</strong> {user[2]}</div>
                <div class="info-row"><strong>Role:</strong> {user[3]}</div>
                <div class="info-row"><strong>Bio:</strong> {user[4]}</div>
                <div class="info-row"><strong>Saldo:</strong> ${user[5]}</div>
            </div>

            <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
                <h3>💡 Dica</h3>
                <p>Você acessou o perfil do usuário ID={user[0]}. Experimente mudar o ID na URL!</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/messages')
@login_required
def messages():
    """Lista mensagens do usuário"""
    user_id = session['user_id']
    c = db.cursor()
    c.execute('''SELECT m.id, u.username, m.subject, m.created_at
                 FROM messages m
                 JOIN users u ON m.sender_id = u.id
                 WHERE m.receiver_id = ?
                 ORDER BY m.created_at DESC''', (user_id,))
    messages_list = c.fetchall()

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>💬 Mensagens</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
            }
            h1 { color: #667eea; margin-bottom: 20px; }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background: #667eea;
                color: white;
            }
            tr:hover { background: #f5f5f5; }
            a {
                color: #667eea;
                text-decoration: none;
            }
            .back-link {
                display: inline-block;
                margin-bottom: 20px;
                color: #667eea;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← Voltar</a>
            <h1>💬 Minhas Mensagens</h1>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>De</th>
                        <th>Assunto</th>
                        <th>Data</th>
                        <th>Ação</th>
                    </tr>
                </thead>
                <tbody>
    '''

    for msg in messages_list:
        html += f'''
                    <tr>
                        <td>{msg[0]}</td>
                        <td>{msg[1]}</td>
                        <td>{msg[2]}</td>
                        <td>{msg[3]}</td>
                        <td><a href="/message/{msg[0]}">Ver</a></td>
                    </tr>
        '''

    html += '''
                </tbody>
            </table>

            <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
                <h3>💡 Dica</h3>
                <p>Observe o ID das mensagens. Experimente acessar IDs diferentes diretamente na URL!</p>
                <p>Exemplo: /message/1, /message/2, /message/3...</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/message/<int:message_id>')
@login_required
def view_message(message_id):
    """
    VULNERÁVEL: IDOR em mensagens
    Permite ler mensagem de qualquer usuário
    """
    c = db.cursor()
    c.execute('''SELECT m.*, u1.username as sender, u2.username as receiver
                 FROM messages m
                 JOIN users u1 ON m.sender_id = u1.id
                 JOIN users u2 ON m.receiver_id = u2.id
                 WHERE m.id = ?''', (message_id,))
    message = c.fetchone()

    if not message:
        return 'Mensagem não encontrada', 404

    # VULNERÁVEL ❌ - Não verifica se usuário é remetente ou destinatário!
    flag_message = ''
    if message[2] != session['user_id']:  # receiver_id
        flag_message = '<div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0;">🚩 FLAG{idor_private_messages} - Você leu uma mensagem privada de outro usuário!</div>'

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>💬 Mensagem</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 800px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
            }}
            h1 {{ color: #667eea; margin-bottom: 20px; }}
            .message-box {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }}
            .back-link {{
                display: inline-block;
                margin-bottom: 20px;
                color: #667eea;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/messages" class="back-link">← Voltar</a>
            <h1>💬 {message[3]}</h1>

            {flag_message}

            <div class="message-box">
                <p><strong>De:</strong> {message[6]}</p>
                <p><strong>Para:</strong> {message[7]}</p>
                <p><strong>Data:</strong> {message[5]}</p>
                <hr style="margin: 15px 0;">
                <p>{message[4]}</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/users')
@login_required
def users_list():
    """Lista todos os usuários"""
    c = db.cursor()
    c.execute('SELECT id, username, email, role FROM users')
    users = c.fetchall()

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>👥 Usuários</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
            }
            h1 { color: #667eea; margin-bottom: 20px; }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background: #667eea;
                color: white;
            }
            tr:hover { background: #f5f5f5; }
            a {
                color: #667eea;
                text-decoration: none;
            }
            .back-link {
                display: inline-block;
                margin-bottom: 20px;
                color: #667eea;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← Voltar</a>
            <h1>👥 Lista de Usuários</h1>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Perfil</th>
                    </tr>
                </thead>
                <tbody>
    '''

    for user in users:
        html += f'''
                    <tr>
                        <td>{user[0]}</td>
                        <td>{user[1]}</td>
                        <td>{user[2]}</td>
                        <td>{user[3]}</td>
                        <td><a href="/profile/{user[0]}">Ver</a></td>
                    </tr>
        '''

    html += '''
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/admin')
@login_required
def admin_panel():
    """
    VULNERÁVEL: Missing Function Level Access Control
    Não verifica se usuário é admin!
    """
    # VULNERÁVEL ❌ - Deveria verificar: if session['role'] != 'admin': return 'Access Denied', 403

    flag_message = ''
    if session['role'] != 'admin':
        flag_message = '<div style="background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0;"><h2>🚩 FLAG{admin_panel_access}</h2><p>Você acessou o painel admin sem ser administrador!</p></div>'

    c = db.cursor()
    c.execute('SELECT id, username, email, role, balance FROM users')
    users = c.fetchall()

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>⚙️ Admin Panel</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
            }}
            h1 {{ color: #dc3545; margin-bottom: 20px; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background: #dc3545;
                color: white;
            }}
            .secret {{
                background: #f8d7da;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border: 2px solid #dc3545;
            }}
            .back-link {{
                display: inline-block;
                margin-bottom: 20px;
                color: #dc3545;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← Voltar</a>
            <h1>⚙️ Painel Administrativo</h1>

            {flag_message}

            <div class="secret">
                <h3>🔒 Informações Sensíveis</h3>
                <p><strong>Database:</strong> postgresql://admin:SuperSecret123@localhost/prod</p>
                <p><strong>API Key:</strong> sk-1234567890abcdef</p>
                <p><strong>Backup Server:</strong> backup.internal.company.com</p>
            </div>

            <h2>👥 Gerenciar Usuários</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Saldo</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
    '''

    for user in users:
        html += f'''
                    <tr>
                        <td>{user[0]}</td>
                        <td>{user[1]}</td>
                        <td>{user[2]}</td>
                        <td>{user[3]}</td>
                        <td>${user[4]}</td>
                        <td>
                            <a href="/admin/edit/{user[0]}">Editar</a> |
                            <a href="/admin/delete/{user[0]}">Deletar</a>
                        </td>
                    </tr>
        '''

    html += '''
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/api/profile', methods=['GET', 'POST'])
@login_required
def api_profile():
    """
    API para atualizar perfil
    VULNERÁVEL: Mass Assignment
    """
    user_id = session['user_id']

    if request.method == 'GET':
        c = db.cursor()
        c.execute('SELECT id, username, email, role, bio, balance FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3],
            'bio': user[4],
            'balance': user[5]
        })

    # POST - Atualizar
    data = request.get_json()

    # VULNERÁVEL ❌ - Mass Assignment!
    # Permite atualizar QUALQUER campo, inclusive role e balance!
    updates = []
    values = []
    for key, value in data.items():
        if key != 'id':  # Não deixa mudar ID
            updates.append(f'{key} = ?')
            values.append(value)

    values.append(user_id)
    query = f'UPDATE users SET {", ".join(updates)} WHERE id = ?'

    c = db.cursor()
    c.execute(query, values)
    db.commit()

    # Verifica se virou admin
    c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    new_role = c.fetchone()[0]

    response = {'message': 'Profile updated successfully'}

    if new_role == 'admin' and session['role'] != 'admin':
        response['flag'] = 'FLAG{privilege_escalation}'
        response['message'] += ' - Você se tornou admin!'
        session['role'] = 'admin'

    return jsonify(response)

if __name__ == '__main__':
    print('=' * 60)
    print('🔐 Broken Access Control - Basic Lab')
    print('=' * 60)
    print('🌐 URL: http://localhost:5030')
    print('📊 Dificuldade: 🟢 Básico')
    print('🎯 Pontos: 10')
    print('')
    print('👥 Usuários de Teste:')
    print('  • alice / password123 (user, ID=1)')
    print('  • bob / password456 (user, ID=2)')
    print('  • admin / admin123 (admin, ID=3)')
    print('  • charlie / charlie789 (user, ID=4)')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{idor_profile_access} - Acesse perfil de outro usuário')
    print('  2. FLAG{idor_private_messages} - Leia mensagem privada')
    print('  3. FLAG{admin_panel_access} - Acesse /admin sem ser admin')
    print('  4. FLAG{privilege_escalation} - Vire admin via API')
    print('')
    print('💡 Dicas:')
    print('  • Mude IDs nas URLs: /profile/1, /profile/2, /profile/3')
    print('  • Acesse /admin diretamente')
    print('  • Use Postman/curl para testar API: POST /api/profile')
    print('  • Tente: {"role": "admin"} na API')
    print('=' * 60)

    app.run(host='0.0.0.0', port=5030, debug=False)
