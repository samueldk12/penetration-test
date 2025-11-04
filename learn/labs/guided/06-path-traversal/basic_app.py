#!/usr/bin/env python3
"""
🎯 Path Traversal - Basic Lab
Laboratório de Vulnerabilidades de Path Traversal

Porta: 5060
Dificuldade: 🟢 Básico
Pontos: 10

VULNERABILIDADES:
1. Path Traversal em file download
2. Directory Traversal em file listing
3. Unrestricted File Upload com path traversal
4. Log file access

FLAGS:
- FLAG{path_traversal_basic} - Acesse /etc/passwd
- FLAG{directory_listing_exposed} - Liste diretório /tmp/secrets/
- FLAG{log_poisoning_ready} - Acesse arquivo de log
"""

from flask import Flask, request, render_template_string, send_file, jsonify
import os
import sqlite3
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'traversal_secret_key_123'

# Configuração
UPLOAD_FOLDER = '/tmp/uploads'
FILES_FOLDER = '/tmp/files'
LOG_FILE = '/tmp/app.log'

# Criar diretórios e arquivos de teste
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)
os.makedirs('/tmp/secrets', exist_ok=True)
os.makedirs('/tmp/admin', exist_ok=True)

# Criar arquivos de teste
def setup_files():
    # Arquivos públicos
    with open(f'{FILES_FOLDER}/public_file.txt', 'w') as f:
        f.write('Este é um arquivo público.\nVocê pode baixar este arquivo normalmente.')

    with open(f'{FILES_FOLDER}/readme.txt', 'w') as f:
        f.write('README\n======\nBem-vindo ao File Manager!\n')

    with open(f'{FILES_FOLDER}/document.pdf', 'w') as f:
        f.write('Fake PDF content here...')

    # Arquivos secretos
    with open('/tmp/secrets/secret_key.txt', 'w') as f:
        f.write('API_KEY=sk-1234567890abcdef\nFLAG{directory_listing_exposed}\n')

    with open('/tmp/secrets/passwords.txt', 'w') as f:
        f.write('admin:SuperSecret123!\nroot:RootPass456!\n')

    # Arquivo admin
    with open('/tmp/admin/config.conf', 'w') as f:
        f.write('DATABASE_URL=postgresql://admin:secret@localhost/prod\n')
        f.write('SECRET_KEY=ultra_secret_key_789\n')

    # Log file
    with open(LOG_FILE, 'w') as f:
        f.write(f'[{datetime.now()}] Application started\n')
        f.write(f'[{datetime.now()}] User admin logged in from 192.168.1.100\n')
        f.write('FLAG{log_poisoning_ready}\n')

setup_files()

# Banco de dados
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()

    # Tabela de arquivos
    c.execute('''CREATE TABLE files
                 (id INTEGER PRIMARY KEY, filename TEXT, filepath TEXT,
                  uploaded_at TEXT, size INTEGER)''')

    # Arquivos iniciais
    files = [
        ('readme.txt', f'{FILES_FOLDER}/readme.txt', '2024-01-01 10:00:00', 1024),
        ('document.pdf', f'{FILES_FOLDER}/document.pdf', '2024-01-02 11:00:00', 2048),
        ('public_file.txt', f'{FILES_FOLDER}/public_file.txt', '2024-01-03 12:00:00', 512),
    ]

    c.executemany('INSERT INTO files (filename, filepath, uploaded_at, size) VALUES (?, ?, ?, ?)', files)
    conn.commit()
    return conn

db = init_db()

def log_request(message):
    """Log de requisições"""
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{datetime.now()}] {message}\n')

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>📁 File Manager - Path Traversal Lab</title>
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
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .lab-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
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
        .feature-card h3 {
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        .feature-card p {
            opacity: 0.9;
            font-size: 0.9em;
        }
        .endpoint {
            background: #f1f3f5;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
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
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 File Manager</h1>
        <p class="subtitle">Sistema de Gerenciamento de Arquivos</p>

        <div class="lab-info">
            <h3>🎯 Informações do Laboratório</h3>
            <p><strong>Dificuldade:</strong> 🟢 Básico</p>
            <p><strong>Pontos:</strong> 10</p>
            <p><strong>Vulnerabilidades:</strong> Path Traversal, Directory Listing, Log Poisoning</p>
            <p><strong>Porta:</strong> 5060</p>
        </div>

        <div class="feature-grid">
            <div class="feature-card" onclick="location.href='/files'">
                <h3>📂 Meus Arquivos</h3>
                <p>Baixe arquivos disponíveis</p>
            </div>

            <div class="feature-card" onclick="location.href='/list'">
                <h3>📋 Listar Diretório</h3>
                <p>Navegue pelos diretórios</p>
            </div>

            <div class="feature-card" onclick="location.href='/upload'">
                <h3>📤 Upload</h3>
                <p>Envie seus arquivos</p>
            </div>

            <div class="feature-card" onclick="location.href='/logs'">
                <h3>📊 Ver Logs</h3>
                <p>Visualize logs do sistema</p>
            </div>
        </div>

        <div class="flag">
            <h3>🚩 Objetivos (Flags)</h3>
            <p>🎯 FLAG 1: Acesse o arquivo /etc/passwd usando path traversal</p>
            <p>🎯 FLAG 2: Liste o conteúdo do diretório /tmp/secrets/</p>
            <p>🎯 FLAG 3: Acesse o arquivo de log do sistema</p>
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 10px;">
            <h3>📚 Endpoints Disponíveis</h3>
            <div class="endpoint">GET <a href="/files">/files</a> - Lista arquivos disponíveis</div>
            <div class="endpoint">GET <a href="/download?file=readme.txt">/download?file=readme.txt</a> - Baixa arquivo</div>
            <div class="endpoint">GET <a href="/list?path=/tmp/files">/list?path=/tmp/files</a> - Lista diretório</div>
            <div class="endpoint">POST /upload - Upload de arquivo</div>
            <div class="endpoint">GET <a href="/logs">/logs</a> - Visualiza logs</div>
        </div>
    </div>
</body>
</html>
'''

FILES_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>📂 Meus Arquivos</title>
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
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; margin-bottom: 30px; }
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
        .btn {
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { background: #5568d3; }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Voltar</a>
        <h1>📂 Meus Arquivos</h1>

        <table>
            <thead>
                <tr>
                    <th>📄 Nome do Arquivo</th>
                    <th>📅 Data</th>
                    <th>💾 Tamanho</th>
                    <th>⬇️ Download</th>
                </tr>
            </thead>
            <tbody>
                {% for file in files %}
                <tr>
                    <td>{{ file[0] }}</td>
                    <td>{{ file[2] }}</td>
                    <td>{{ file[3] }} bytes</td>
                    <td><a href="/download?file={{ file[0] }}" class="btn">Download</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
            <h3>💡 Dica</h3>
            <p>Experimente modificar o parâmetro <code>file</code> na URL para acessar outros arquivos do sistema...</p>
            <p>Exemplos: <code>../</code>, <code>../../</code>, <code>../../../../etc/passwd</code></p>
        </div>
    </div>
</body>
</html>
'''

LIST_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>📋 Listar Diretório</title>
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
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; margin-bottom: 20px; }
        .form-group {
            margin: 20px 0;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
        }
        button {
            background: #667eea;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
        }
        button:hover { background: #5568d3; }
        .result {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
        }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Voltar</a>
        <h1>📋 Listar Diretório</h1>

        <form method="GET">
            <div class="form-group">
                <label>Caminho do Diretório:</label>
                <input type="text" name="path" value="{{ path }}" placeholder="/tmp/files">
            </div>
            <button type="submit">📂 Listar</button>
        </form>

        {% if result %}
        <div class="result">{{ result }}</div>
        {% endif %}

        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
            <h3>💡 Dicas</h3>
            <p>• Tente navegar para outros diretórios usando path traversal</p>
            <p>• Exemplos: <code>/tmp/secrets/</code>, <code>/tmp/admin/</code>, <code>/etc/</code></p>
            <p>• Use <code>../</code> para subir níveis de diretório</p>
        </div>
    </div>
</body>
</html>
'''

UPLOAD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>📤 Upload de Arquivo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; margin-bottom: 20px; }
        .form-group {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 10px;
            font-weight: bold;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
        }
        button {
            background: #667eea;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            width: 100%;
        }
        button:hover { background: #5568d3; }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Voltar</a>
        <h1>📤 Upload de Arquivo</h1>

        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label>Arquivo:</label>
                <input type="file" name="file" required>
            </div>

            <div class="form-group">
                <label>Caminho de Destino (opcional):</label>
                <input type="text" name="destination" placeholder="uploads/" value="uploads/">
            </div>

            <button type="submit">📤 Fazer Upload</button>
        </form>

        {% if message %}
        <div class="message {{ message_type }}">{{ message }}</div>
        {% endif %}

        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 10px;">
            <h3>💡 Dica</h3>
            <p>O campo "Caminho de Destino" permite especificar onde o arquivo será salvo...</p>
            <p>Experimente usar <code>../</code> para salvar em outros diretórios!</p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Página inicial"""
    return HOME_TEMPLATE

@app.route('/files')
def files():
    """Lista arquivos disponíveis"""
    c = db.cursor()
    c.execute('SELECT filename, filepath, uploaded_at, size FROM files')
    files_list = c.fetchall()

    return render_template_string(FILES_TEMPLATE, files=files_list)

@app.route('/download')
def download():
    """
    VULNERÁVEL: Path Traversal
    Permite download de qualquer arquivo do sistema
    """
    filename = request.args.get('file', 'readme.txt')

    # VULNERÁVEL ❌ - Sem validação de path traversal!
    filepath = os.path.join(FILES_FOLDER, filename)

    log_request(f'Download request: {filename}')

    try:
        # Tenta abrir o arquivo (permite path traversal!)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)

        # Se não existe em FILES_FOLDER, tenta caminho absoluto
        # Isso permite acessar /etc/passwd diretamente!
        if os.path.exists(filename):
            content = open(filename, 'r').read()

            # FLAG: Se acessou /etc/passwd
            if 'root:' in content and 'bin:' in content:
                content += '\n\n🚩 FLAG{path_traversal_basic}\n'

            return f'<pre>{content}</pre>'

        return 'Arquivo não encontrado', 404

    except Exception as e:
        return f'Erro ao ler arquivo: {str(e)}', 500

@app.route('/list')
def list_directory():
    """
    VULNERÁVEL: Directory Traversal
    Lista conteúdo de qualquer diretório
    """
    path = request.args.get('path', FILES_FOLDER)

    # VULNERÁVEL ❌ - Sem validação de diretório!
    log_request(f'List directory request: {path}')

    try:
        if os.path.isdir(path):
            files = os.listdir(path)
            result = f'📂 Conteúdo de: {path}\n\n'

            for f in files:
                full_path = os.path.join(path, f)
                if os.path.isdir(full_path):
                    result += f'📁 {f}/\n'
                else:
                    size = os.path.getsize(full_path)
                    result += f'📄 {f} ({size} bytes)\n'

            # FLAG: Se listou /tmp/secrets/
            if path == '/tmp/secrets' or path == '/tmp/secrets/':
                result += '\n🚩 Você encontrou o diretório secreto!\n'
                result += 'FLAG{directory_listing_exposed}\n'

            return render_template_string(LIST_TEMPLATE, path=path, result=result)
        else:
            return render_template_string(LIST_TEMPLATE, path=path, result='Caminho não é um diretório')

    except Exception as e:
        return render_template_string(LIST_TEMPLATE, path=path, result=f'Erro: {str(e)}')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    VULNERÁVEL: Unrestricted File Upload + Path Traversal
    Permite upload para qualquer diretório
    """
    if request.method == 'GET':
        return render_template_string(UPLOAD_TEMPLATE)

    file = request.files.get('file')
    destination = request.form.get('destination', 'uploads/')

    if not file:
        return render_template_string(UPLOAD_TEMPLATE,
                                      message='Nenhum arquivo enviado',
                                      message_type='error')

    # VULNERÁVEL ❌ - Path traversal no destino!
    dest_path = os.path.join('/tmp', destination, file.filename)

    # Cria diretório se não existe
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Salva arquivo
    file.save(dest_path)

    log_request(f'File uploaded: {file.filename} to {dest_path}')

    return render_template_string(UPLOAD_TEMPLATE,
                                  message=f'Arquivo enviado com sucesso para: {dest_path}',
                                  message_type='success')

@app.route('/logs')
def view_logs():
    """
    VULNERÁVEL: Log File Access
    Permite visualizar arquivo de log
    """
    log_file = request.args.get('file', LOG_FILE)

    # VULNERÁVEL ❌ - Permite especificar qualquer arquivo de log!
    try:
        with open(log_file, 'r') as f:
            content = f.read()

        # FLAG: Se acessou o log file
        if log_file == LOG_FILE and 'FLAG{log_poisoning_ready}' in content:
            content += '\n\n🚩 Você acessou o arquivo de log!\n'

        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>📊 Logs do Sistema</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }}
                h1 {{ color: #667eea; margin-bottom: 20px; }}
                pre {{
                    background: #1e1e1e;
                    color: #00ff00;
                    padding: 20px;
                    border-radius: 10px;
                    overflow-x: auto;
                    font-family: 'Courier New', monospace;
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
                <h1>📊 Logs do Sistema</h1>
                <p><strong>Arquivo:</strong> {log_file}</p>
                <pre>{content}</pre>
            </div>
        </body>
        </html>
        '''
        return html

    except Exception as e:
        return f'Erro ao ler log: {str(e)}', 500

if __name__ == '__main__':
    print('=' * 60)
    print('🎯 Path Traversal - Basic Lab')
    print('=' * 60)
    print('🌐 URL: http://localhost:5060')
    print('📊 Dificuldade: 🟢 Básico')
    print('🎯 Pontos: 10')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{path_traversal_basic} - Acesse /etc/passwd')
    print('  2. FLAG{directory_listing_exposed} - Liste /tmp/secrets/')
    print('  3. FLAG{log_poisoning_ready} - Acesse arquivo de log')
    print('')
    print('💡 Dicas:')
    print('  • Use ../../../etc/passwd no parâmetro file')
    print('  • Tente listar diretórios sensíveis')
    print('  • Experimente path traversal no upload')
    print('=' * 60)

    app.run(host='0.0.0.0', port=5060, debug=False)
