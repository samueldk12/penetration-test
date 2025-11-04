#!/usr/bin/env python3
"""
SQL Injection - Intermediate Level
===================================

Aplicação: E-commerce Platform
Porta: 5011
Dificuldade: 🟡 Intermediário (25 pontos)

Vulnerabilidades:
- SQLi em múltiplos endpoints (search, products, reviews)
- Filtros básicos (bypassáveis)
- UNION-based injection
- Stored SQL Injection em comentários
- SQLi em diferentes contextos (GET, POST, JSON)

Objetivo:
1. Bypassar filtros de segurança
2. Extrair dados de múltiplas tabelas
3. Explorar SQLi em reviews/comments (stored)
4. Acessar painel admin
5. Extrair informações de pagamento

Dica: Os filtros bloqueiam algumas palavras, mas podem ser bypassados!
"""

from flask import Flask, request, render_template_string, jsonify, session
import sqlite3
import os
import hashlib
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'intermediate-sqli-e-commerce-2024'

DB_PATH = '/tmp/intermediate_sqli.db'

def init_db():
    """Inicializa banco de dados do e-commerce"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabela de usuários
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'customer',
            address TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabela de produtos
    c.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            stock INTEGER DEFAULT 0,
            image_url TEXT
        )
    ''')

    # Tabela de pedidos
    c.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total_price REAL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    # Tabela de reviews (VULNERÁVEL a Stored SQLi)
    c.execute('''
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            rating INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Tabela de pagamentos (dados sensíveis)
    c.execute('''
        CREATE TABLE payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_id INTEGER,
            card_number TEXT,
            card_holder TEXT,
            cvv TEXT,
            amount REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (order_id) REFERENCES orders(id)
        )
    ''')

    # Inserir usuários
    users_data = [
        ('admin', hashlib.md5('Admin@2024!'.encode()).hexdigest(), 'admin@eshop.com', 'admin', '123 Admin St', '555-0000'),
        ('alice', hashlib.md5('alice123'.encode()).hexdigest(), 'alice@example.com', 'customer', '456 Alice Ave', '555-0001'),
        ('bob', hashlib.md5('bob456'.encode()).hexdigest(), 'bob@example.com', 'customer', '789 Bob Blvd', '555-0002'),
        ('charlie', hashlib.md5('charlie789'.encode()).hexdigest(), 'charlie@example.com', 'vendor', '321 Charlie Ct', '555-0003'),
    ]

    for username, password, email, role, address, phone in users_data:
        c.execute('INSERT INTO users (username, password, email, role, address, phone) VALUES (?, ?, ?, ?, ?, ?)',
                  (username, password, email, role, address, phone))

    # Inserir produtos
    products_data = [
        ('Laptop Dell XPS 15', 'High-performance laptop', 1299.99, 'Electronics', 15, '/img/laptop.jpg'),
        ('iPhone 14 Pro', 'Latest Apple smartphone', 999.99, 'Electronics', 30, '/img/iphone.jpg'),
        ('Sony WH-1000XM5', 'Noise-cancelling headphones', 349.99, 'Audio', 50, '/img/headphones.jpg'),
        ('MacBook Air M2', 'Thin and light laptop', 1199.99, 'Electronics', 20, '/img/macbook.jpg'),
        ('Samsung Galaxy S23', 'Android flagship', 899.99, 'Electronics', 25, '/img/samsung.jpg'),
        ('iPad Pro 12.9"', 'Professional tablet', 1099.99, 'Tablets', 18, '/img/ipad.jpg'),
        ('AirPods Pro', 'True wireless earbuds', 249.99, 'Audio', 100, '/img/airpods.jpg'),
        ('Dell Monitor 27"', '4K monitor', 449.99, 'Accessories', 40, '/img/monitor.jpg'),
    ]

    for name, desc, price, cat, stock, img in products_data:
        c.execute('INSERT INTO products (name, description, price, category, stock, image_url) VALUES (?, ?, ?, ?, ?, ?)',
                  (name, desc, price, cat, stock, img))

    # Inserir alguns pedidos
    orders_data = [
        (2, 1, 1, 1299.99, 'completed'),  # alice comprou laptop
        (2, 3, 1, 349.99, 'completed'),   # alice comprou headphones
        (3, 2, 1, 999.99, 'pending'),     # bob comprou iphone
    ]

    for user_id, product_id, qty, total, status in orders_data:
        c.execute('INSERT INTO orders (user_id, product_id, quantity, total_price, status) VALUES (?, ?, ?, ?, ?)',
                  (user_id, product_id, qty, total, status))

    # Inserir reviews
    reviews_data = [
        (1, 2, 5, 'Amazing laptop! Very fast and reliable.'),
        (2, 2, 4, 'Great phone, but battery could be better.'),
        (3, 3, 5, 'Best headphones I ever owned!'),
    ]

    for product_id, user_id, rating, comment in reviews_data:
        c.execute('INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
                  (product_id, user_id, rating, comment))

    # Inserir dados de pagamento (sensíveis)
    payments_data = [
        (2, 1, '4532-1234-5678-9010', 'Alice Smith', '123', 1299.99),
        (2, 2, '4532-9876-5432-1098', 'Alice Smith', '456', 349.99),
        (3, 3, '5412-7531-9876-5432', 'Bob Johnson', '789', 999.99),
    ]

    for user_id, order_id, card, holder, cvv, amount in payments_data:
        c.execute('INSERT INTO payments (user_id, order_id, card_number, card_holder, cvv, amount) VALUES (?, ?, ?, ?, ?, ?)',
                  (user_id, order_id, card, holder, cvv, amount))

    conn.commit()
    conn.close()
    print("[+] E-commerce database initialized")


def weak_waf(input_str):
    """
    Simula WAF fraco que bloqueia apenas palavras-chave exatas
    BYPASSÁVEL com case variation, comments, etc.
    """
    blacklist = ['OR', 'AND', '--', '#', 'UNION', 'SELECT', 'DROP', 'DELETE', 'UPDATE', 'INSERT']

    for bad_word in blacklist:
        if bad_word in input_str.upper():
            # Apenas log, não bloqueia completamente
            print(f"[WAF] Palavra suspeita detectada: {bad_word}")
            # Torna mais difícil mas não impossível
            if input_str.upper().count(bad_word) > 2:
                return None  # Bloqueia apenas se muito óbvio

    return input_str


@app.route('/')
def index():
    """Página inicial da loja"""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>E-Shop - Intermediate SQLi Lab</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial; background: #f5f5f5; }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                text-align: center;
            }
            .badge { background: #ffc107; color: #000; padding: 5px 10px; border-radius: 5px; font-size: 12px; }
            .container { max-width: 1200px; margin: 30px auto; padding: 20px; }
            .nav {
                background: white;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .nav a {
                color: #667eea;
                text-decoration: none;
                margin: 0 15px;
                font-weight: 500;
            }
            .card {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .search-box {
                display: flex;
                gap: 10px;
                margin: 20px 0;
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
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛒 E-Shop <span class="badge">INTERMEDIATE</span></h1>
            <p>Professional E-commerce Platform</p>
        </div>

        <div class="container">
            <div class="nav">
                <a href="/">🏠 Home</a>
                <a href="/products">📦 Products</a>
                <a href="/search">🔍 Search</a>
                <a href="/login">🔐 Login</a>
                <a href="/admin">⚙️ Admin</a>
                <a href="/about">ℹ️ About</a>
            </div>

            <div class="card">
                <h2>🎯 Objetivos do Lab</h2>
                <ul style="margin: 20px; line-height: 2;">
                    <li>✅ Bypassar filtros WAF básicos</li>
                    <li>✅ Explorar SQLi em múltiplos endpoints</li>
                    <li>✅ UNION-based data extraction</li>
                    <li>✅ Stored SQLi em reviews</li>
                    <li>✅ Acessar painel admin</li>
                    <li>✅ Extrair dados de cartão de crédito</li>
                </ul>
            </div>

            <div class="card">
                <h2>🔍 Quick Search</h2>
                <form action="/search" method="GET">
                    <div class="search-box">
                        <input type="text" name="q" placeholder="Search products...">
                        <button type="submit">Search</button>
                    </div>
                </form>
            </div>

            <div class="card" style="background: #fff3cd;">
                <h3>💡 Dicas</h3>
                <p style="margin-top: 10px;">
                    Esta aplicação tem um WAF básico que bloqueia algumas palavras-chave.
                    Tente usar case variation (<code>oR</code>, <code>UnIoN</code>), comentários (<code>/**/</code>)
                    ou outras técnicas de bypass!
                </p>
            </div>
        </div>
    </body>
    </html>
    ''')


@app.route('/products')
def products():
    """Lista de produtos com filtro"""
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Base query
    query = "SELECT id, name, description, price, category, stock FROM products WHERE 1=1"

    # VULNERÁVEL ❌ - Concatenação direta
    if category:
        # Filtro WAF fraco
        if weak_waf(category) is not None:
            query += f" AND category = '{category}'"

    if min_price:
        query += f" AND price >= {min_price}"

    if max_price:
        query += f" AND price <= {max_price}"

    print(f"[DEBUG] Products query: {query}")

    try:
        c.execute(query)
        results = c.fetchall()

        html = '''
        <html>
        <head>
            <title>Products - E-Shop</title>
            <style>
                body { font-family: Arial; padding: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .filter { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .products { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; }
                .product {
                    background: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }
                .price { color: #4caf50; font-size: 24px; font-weight: bold; }
                input, select { padding: 10px; margin: 5px; }
                button { padding: 10px 20px; background: #667eea; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📦 Products</h1>

                <div class="filter">
                    <form method="GET">
                        <input type="text" name="category" placeholder="Category" value="''' + category + '''">
                        <input type="number" name="min_price" placeholder="Min Price" value="''' + min_price + '''">
                        <input type="number" name="max_price" placeholder="Max Price" value="''' + max_price + '''">
                        <button type="submit">Filter</button>
                        <a href="/products"><button type="button">Clear</button></a>
                    </form>
                    <p style="margin-top: 10px; font-size: 12px; color: #666;">
                        💡 Dica: O filtro de categoria tem proteção WAF. Tente bypassar!
                    </p>
                </div>

                <div class="products">
        '''

        for product in results:
            html += f'''
            <div class="product">
                <h3>{product[1]}</h3>
                <p>{product[2]}</p>
                <div class="price">${product[3]}</div>
                <p><strong>Category:</strong> {product[4]}</p>
                <p><strong>Stock:</strong> {product[5]}</p>
                <a href="/product/{product[0]}"><button>View Details</button></a>
            </div>
            '''

        html += '''
                </div>
                <p style="margin-top: 20px;"><a href="/">← Back to Home</a></p>
            </div>
        </body>
        </html>
        '''
        return render_template_string(html)

    except sqlite3.Error as e:
        return f'<h1>Database Error</h1><p>{str(e)}</p><p>Query: {query}</p><a href="/products">Back</a>', 500
    finally:
        conn.close()


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Detalhes do produto com reviews"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Busca produto
    c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = c.fetchone()

    if not product:
        return "Product not found", 404

    # Busca reviews - VULNERÁVEL a Stored SQLi
    c.execute(f"SELECT r.id, r.rating, r.comment, u.username, r.created_at FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = {product_id}")
    reviews = c.fetchall()

    conn.close()

    html = f'''
    <html>
    <head>
        <title>{product[1]} - E-Shop</title>
        <style>
            body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            .price {{ color: #4caf50; font-size: 32px; font-weight: bold; margin: 20px 0; }}
            .reviews {{ margin-top: 40px; }}
            .review {{ background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            textarea {{ width: 100%; padding: 10px; margin: 10px 0; }}
            button {{ padding: 10px 20px; background: #667eea; color: white; border: none; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>{product[1]}</h1>
            <p>{product[2]}</p>
            <div class="price">${product[3]}</div>
            <p><strong>Category:</strong> {product[4]}</p>
            <p><strong>Stock:</strong> {product[5]} units</p>

            <div class="reviews">
                <h2>⭐ Customer Reviews</h2>
    '''

    for review in reviews:
        html += f'''
        <div class="review">
            <strong>{review[3]}</strong> - {'⭐' * review[1]}<br>
            <p>{review[2]}</p>
            <small>{review[4]}</small>
        </div>
        '''

    html += f'''
                <h3>Add Your Review</h3>
                <form method="POST" action="/api/review">
                    <input type="hidden" name="product_id" value="{product_id}">
                    <select name="rating" required>
                        <option value="">Select Rating</option>
                        <option value="1">⭐ 1 Star</option>
                        <option value="2">⭐⭐ 2 Stars</option>
                        <option value="3">⭐⭐⭐ 3 Stars</option>
                        <option value="4">⭐⭐⭐⭐ 4 Stars</option>
                        <option value="5">⭐⭐⭐⭐⭐ 5 Stars</option>
                    </select><br>
                    <textarea name="comment" placeholder="Your review..." rows="4" required></textarea><br>
                    <input type="text" name="username" placeholder="Your name" required><br>
                    <button type="submit">Submit Review</button>
                </form>
            </div>

            <p style="margin-top: 20px;"><a href="/products">← Back to Products</a></p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)


@app.route('/api/review', methods=['POST'])
def submit_review():
    """
    VULNERÁVEL: Stored SQL Injection em reviews
    O comentário é armazenado e depois executado em outras queries
    """
    product_id = request.form.get('product_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment')  # VULNERÁVEL ❌ - Sem sanitização
    username = request.form.get('username')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Busca ou cria usuário
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if not user:
        # Cria novo usuário guest
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                  (username, 'guest', f'{username}@guest.com', 'customer'))
        user_id = c.lastrowid
    else:
        user_id = user[0]

    # Insere review - Usa prepared statement aqui (mas será vulnerável quando recuperado)
    c.execute("INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)",
              (product_id, user_id, rating, comment))

    conn.commit()
    conn.close()

    return f'<h1>✅ Review Submitted!</h1><p>Thank you for your review.</p><a href="/product/{product_id}">← Back</a>'


@app.route('/search')
def search():
    """
    VULNERÁVEL: SQL Injection em busca com WAF fraco
    """
    query = request.args.get('q', '')

    html = '''
    <html>
    <head>
        <title>Search - E-Shop</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            .search-box { margin: 20px 0; }
            input { padding: 12px; width: 400px; font-size: 14px; }
            button { padding: 12px 24px; background: #667eea; color: white; border: none; cursor: pointer; }
            .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .warning { background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>🔍 Search Products</h1>
        <div class="search-box">
            <form method="GET">
                <input type="text" name="q" value="''' + query + '''" placeholder="Search...">
                <button type="submit">Search</button>
            </form>
        </div>
        <div class="warning">
            ⚠️ Sistema protegido por WAF. Tentativas de ataque serão bloqueadas.
        </div>
    '''

    if query:
        # WAF check (fraco)
        filtered = weak_waf(query)

        if filtered is None:
            html += '<div style="background: #ffebee; padding: 15px;">🚫 WAF: Query bloqueada por conter padrões suspeitos!</div>'
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()

            # VULNERÁVEL ❌
            sql_query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{filtered}%' OR description LIKE '%{filtered}%'"

            print(f"[DEBUG] Search query: {sql_query}")

            try:
                c.execute(sql_query)
                results = c.fetchall()

                html += f'<h2>Results for "{query}":</h2>'

                if results:
                    for row in results:
                        html += f'''
                        <div class="result">
                            <h3>{row[1]}</h3>
                            <p>{row[2]}</p>
                            <p><strong>Price:</strong> ${row[3]}</p>
                            <a href="/product/{row[0]}">View Details</a>
                        </div>
                        '''
                else:
                    html += '<p>No results found.</p>'

            except sqlite3.Error as e:
                html += f'<div style="background: #ffebee; padding: 15px;"><strong>Database Error:</strong><br><code>{str(e)}</code></div>'
                html += f'<div style="background: #f5f5f5; padding: 15px; margin-top: 10px;"><strong>Query:</strong><br><code>{sql_query}</code></div>'

            finally:
                conn.close()

    html += '<p><a href="/">← Back to Home</a></p></body></html>'
    return render_template_string(html)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login com hash MD5 (ainda vulnerável a SQLi)"""
    if request.method == 'GET':
        return '''
        <html>
        <head><title>Login - E-Shop</title>
        <style>
            body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 400px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
        </head>
        <body>
            <div class="container">
                <h2>🔐 Login</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <p style="margin-top: 20px;"><a href="/">← Back</a></p>
            </div>
        </body>
        </html>
        '''

    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # VULNERÁVEL ❌ - Mesmo com hash
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"

    print(f"[DEBUG] Login query: {query}")

    try:
        c.execute(query)
        user = c.fetchone()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]

            if user[4] == 'admin':
                return '<h1>✅ Admin Login Success!</h1><p>🚩 FLAG{intermediate_sqli_admin_access}</p><a href="/admin">Go to Admin Panel</a>'
            else:
                return f'<h1>✅ Login Success!</h1><p>Welcome {user[1]}!</p><a href="/">Home</a>'
        else:
            return '<h1>❌ Login Failed</h1><a href="/login">Try again</a>'

    except sqlite3.Error as e:
        return f'<h1>Error</h1><p>{str(e)}</p><p>Query: {query}</p>', 500
    finally:
        conn.close()


@app.route('/admin')
def admin():
    """Painel admin - requer login admin"""
    if session.get('role') != 'admin':
        return '<h1>⛔ Access Denied</h1><p>Admin access required</p><a href="/login">Login</a>', 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Pega estatísticas
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM orders")
    total_orders = c.fetchone()[0]

    c.execute("SELECT SUM(total_price) FROM orders")
    total_revenue = c.fetchone()[0] or 0

    c.execute("SELECT * FROM payments ORDER BY created_at DESC LIMIT 5")
    recent_payments = c.fetchall()

    conn.close()

    return f'''
    <html>
    <head><title>Admin Panel</title>
    <style>
        body {{ font-family: Arial; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat {{ background: white; padding: 30px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .stat h2 {{ color: #667eea; font-size: 48px; margin: 10px 0; }}
        table {{ width: 100%; background: white; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        .flag {{ background: #ffd700; padding: 15px; border-radius: 5px; margin: 20px 0; font-weight: bold; text-align: center; }}
    </style>
    </head>
    <body>
        <div class="container">
            <h1>⚙️ Admin Panel</h1>

            <div class="flag">
                🚩 FLAG{{intermediate_sqli_payment_data}}<br>
                Você acessou dados sensíveis de pagamento!
            </div>

            <div class="stats">
                <div class="stat">
                    <p>Total Users</p>
                    <h2>{total_users}</h2>
                </div>
                <div class="stat">
                    <p>Total Orders</p>
                    <h2>{total_orders}</h2>
                </div>
                <div class="stat">
                    <p>Revenue</p>
                    <h2>${total_revenue:.2f}</h2>
                </div>
            </div>

            <h2>Recent Payments</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>User ID</th>
                    <th>Card Number</th>
                    <th>Holder</th>
                    <th>CVV</th>
                    <th>Amount</th>
                    <th>Date</th>
                </tr>
                {''.join([f'<tr><td>{p[0]}</td><td>{p[1]}</td><td>{p[3]}</td><td>{p[4]}</td><td>{p[5]}</td><td>${p[6]}</td><td>{p[7]}</td></tr>' for p in recent_payments])}
            </table>

            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    '''


@app.route('/about')
def about():
    """Informações sobre o lab"""
    return '''
    <html>
    <head>
        <title>About - E-Shop</title>
        <style>
            body { font-family: Arial; padding: 40px; max-width: 900px; margin: 0 auto; }
            h1 { color: #667eea; }
            .section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
            pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
            code { background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>ℹ️ About This Lab</h1>

        <div class="section">
            <h2>🎯 Objetivos</h2>
            <ul>
                <li>Bypassar WAF básico</li>
                <li>Explorar SQLi em diferentes contextos</li>
                <li>UNION-based extraction</li>
                <li>Stored SQLi</li>
                <li>Acessar dados sensíveis</li>
            </ul>
        </div>

        <div class="section">
            <h2>🚩 Flags</h2>
            <ul>
                <li><code>FLAG{intermediate_sqli_admin_access}</code></li>
                <li><code>FLAG{intermediate_sqli_payment_data}</code></li>
                <li><code>FLAG{intermediate_sqli_union_extraction}</code></li>
                <li><code>FLAG{intermediate_sqli_stored}</code></li>
            </ul>
        </div>

        <div class="section">
            <h2>💡 Técnicas de Bypass</h2>
            <pre>
# Case Variation
oR, Or, Or, uNiOn, UnIoN

# Comentários
/**/OR/**/
UN/**/ION/**/SE/**/LECT

# Equivalentes
|| em vez de OR
&& em vez de AND

# Encoding
%6fR = oR

# Espaços alternativos
%0A (newline)
%09 (tab)
            </pre>
        </div>

        <div class="section">
            <h2>🔍 Endpoints Vulneráveis</h2>
            <ul>
                <li><code>/login</code> - Authentication bypass</li>
                <li><code>/search</code> - UNION-based SQLi</li>
                <li><code>/products</code> - Filter injection</li>
                <li><code>/api/review</code> - Stored SQLi</li>
            </ul>
        </div>

        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("=" * 80)
    print("SQL INJECTION - INTERMEDIATE LEVEL LAB")
    print("=" * 80)
    print("\n🛒 Aplicação: E-commerce Platform")
    print("\n🎯 Objetivos:")
    print("  1. Bypassar WAF básico")
    print("  2. Login como admin")
    print("  3. Extrair dados de pagamento")
    print("  4. Explorar Stored SQLi em reviews")
    print("\n🚩 Flags:")
    print("  - FLAG{intermediate_sqli_admin_access}")
    print("  - FLAG{intermediate_sqli_payment_data}")
    print("  - FLAG{intermediate_sqli_union_extraction}")
    print("  - FLAG{intermediate_sqli_stored}")
    print("\n💡 Dicas:")
    print("  - WAF bloqueia OR, AND, UNION (case-sensitive)")
    print("  - Tente: oR, Or, /**/OR/**/")
    print("  - Reviews são armazenados e depois usados em queries")
    print("\n" + "=" * 80)

    init_db()

    print("\n[+] Servidor rodando em http://localhost:5011")
    print("[*] Pressione Ctrl+C para parar\n")

    app.run(host='0.0.0.0', port=5011, debug=True)
