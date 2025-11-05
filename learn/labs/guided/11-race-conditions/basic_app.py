#!/usr/bin/env python3
"""
⏱️ Race Conditions - Basic Lab
Laboratório de Vulnerabilidades de Race Condition

Porta: 5110
Dificuldade: 🟡 Intermediário
Pontos: 15

VULNERABILIDADES:
1. Limit overrun em uso de cupons
2. Double spending em compras
3. TOCTOU em transferências
4. Rate limit bypass

FLAGS:
- FLAG{race_limit_overrun} - Use cupom mais de 1 vez
- FLAG{race_double_spending} - Compre 2 items com crédito para 1
- FLAG{race_toctou} - Transfira mais que o saldo

⚠️  IMPORTANTE: Esta aplicação é INTENCIONALMENTE vulnerável!
    Delays artificiais facilitam exploitation.
"""

from flask import Flask, request, render_template_string, session
import time
import sqlite3
from functools import wraps
import hashlib

app = Flask(__name__)
app.secret_key = 'race_condition_secret_key'

# Banco de dados em memória (não thread-safe!)
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()

    # Tabela de usuários
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                  password TEXT, balance REAL)''')

    # Tabela de cupons
    c.execute('''CREATE TABLE coupons
                 (code TEXT PRIMARY KEY, discount INTEGER,
                  max_uses INTEGER, current_uses INTEGER)''')

    # Tabela de itens
    c.execute('''CREATE TABLE items
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER)''')

    # Tabela de compras
    c.execute('''CREATE TABLE purchases
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                  item_id INTEGER, timestamp TEXT)''')

    # Usuários de teste
    users = [
        (1, 'alice', hashlib.md5(b'password123').hexdigest(), 100.0),
        (2, 'bob', hashlib.md5(b'password456').hexdigest(), 50.0),
    ]
    c.executemany('INSERT INTO users VALUES (?, ?, ?, ?)', users)

    # Cupons
    coupons = [
        ('SAVE20', 20, 1, 0),  # 20% off, 1 uso apenas
        ('FIRST10', 10, 1, 0),  # 10% off, 1 uso apenas
    ]
    c.executemany('INSERT INTO coupons VALUES (?, ?, ?, ?)', coupons)

    # Itens
    items = [
        (1, 'Premium Item', 80.0, 10),
        (2, 'Special Edition', 60.0, 5),
        (3, 'Limited Item', 90.0, 3),
    ]
    c.executemany('INSERT INTO items VALUES (?, ?, ?, ?)', items)

    conn.commit()
    return conn

db = init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return render_template_string('<h1>Login Required</h1><a href="/login">Login</a>')
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>⏱️ Race Conditions Lab</title>
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
        .balance {
            font-size: 1.5em;
            color: #28a745;
            font-weight: bold;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .item {
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }
        button:hover { background: #5568d3; }
        input {
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 8px;
            width: 200px;
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
            font-family: monospace;
            overflow-x: auto;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛒 E-Commerce Store</h1>

        <div class="user-info">
            <strong>👤 Logado como:</strong> {{ username }} |
            <span class="balance">💰 ${{ balance }}</span> |
            <a href="/logout">Sair</a>
        </div>

        {% if flag %}
        <div class="flag">
            <h3>🚩 {{ flag }}</h3>
        </div>
        {% endif %}

        <div class="section">
            <h2>🛍️ Items Disponíveis</h2>
            {% for item in items %}
            <div class="item">
                <div>
                    <strong>{{ item[1] }}</strong> - ${{ item[2] }}
                    <br><small>Estoque: {{ item[3] }}</small>
                </div>
                <form method="POST" action="/buy" style="display: inline;">
                    <input type="hidden" name="item_id" value="{{ item[0] }}">
                    <button type="submit">Comprar</button>
                </form>
            </div>
            {% endfor %}
        </div>

        <div class="section">
            <h2>🎟️ Aplicar Cupom</h2>
            <form method="POST" action="/apply_coupon">
                <input type="text" name="coupon_code" placeholder="Código do cupom" required>
                <button type="submit">Aplicar</button>
            </form>
            <p style="margin-top: 10px;"><small>Cupons disponíveis: SAVE20 (20% off), FIRST10 (10% off)</small></p>
        </div>

        <div class="section">
            <h2>💸 Transferir Créditos</h2>
            <form method="POST" action="/transfer">
                <input type="text" name="to_user" placeholder="Nome do usuário" required>
                <input type="number" name="amount" placeholder="Valor" step="0.01" required>
                <button type="submit">Transferir</button>
            </form>
        </div>

        <div class="warning">
            <h3>⚠️ Vulnerabilidades de Race Condition</h3>
            <p><strong>Esta aplicação tem delays artificiais entre CHECK e USE!</strong></p>
            <br>
            <p><strong>💡 Objetivos:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>1️⃣ Use cupom SAVE20 mais de 1 vez (limite: 1 uso)</li>
                <li>2️⃣ Compre 2 Premium Items ($80 cada) com saldo de $100</li>
                <li>3️⃣ Transfira $200 com saldo de $100</li>
            </ul>
        </div>

        <div class="section">
            <h3>🧪 Como Explorar Race Conditions</h3>

            <p><strong>Método 1: Python Script</strong></p>
            <div class="code">
import requests, threading<br>
<br>
URL = 'http://localhost:5110/apply_coupon'<br>
COOKIE = {'session': 'your_session_cookie'}<br>
DATA = {'coupon_code': 'SAVE20'}<br>
<br>
def exploit():<br>
&nbsp;&nbsp;for _ in range(10):<br>
&nbsp;&nbsp;&nbsp;&nbsp;threading.Thread(target=lambda: requests.post(URL, data=DATA, cookies=COOKIE)).start()
            </div>

            <p><strong>Método 2: Burp Suite</strong></p>
            <p>1. Capture request no Burp Proxy</p>
            <p>2. Send to Repeater (Ctrl+R)</p>
            <p>3. Duplicate tab 20 vezes</p>
            <p>4. Right-click → "Send group in parallel"</p>

            <p><strong>Método 3: cURL + Bash</strong></p>
            <div class="code">
for i in {1..20}; do<br>
&nbsp;&nbsp;curl -X POST http://localhost:5110/buy \<br>
&nbsp;&nbsp;&nbsp;&nbsp;-d "item_id=1" \<br>
&nbsp;&nbsp;&nbsp;&nbsp;-b "session=your_cookie" &<br>
done<br>
wait
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
    <title>🔐 Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
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
        h1 { color: #667eea; margin-bottom: 30px; text-align: center; }
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
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .info {
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
        <div class="info">
            <strong>Usuários de Teste:</strong><br>
            • alice / password123 ($100)<br>
            • bob / password456 ($50)
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    c = db.cursor()

    c.execute('SELECT username, balance FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    c.execute('SELECT * FROM items WHERE stock > 0')
    items = c.fetchall()

    flag = session.pop('flag', None)

    return render_template_string(HOME_TEMPLATE,
                                  username=user[0],
                                  balance=user[1],
                                  items=items,
                                  flag=flag)

@app.route('/login', methods=['GET', 'POST'])
def login():
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
        return render_template_string('<script>location.href="/"</script>')
    else:
        return render_template_string(LOGIN_TEMPLATE, error='Credenciais inválidas')

@app.route('/logout')
def logout():
    session.clear()
    return render_template_string('<script>location.href="/login"</script>')

@app.route('/buy', methods=['POST'])
@login_required
def buy_item():
    """
    VULNERÁVEL: TOCTOU em compra de items
    Delay entre CHECK (saldo) e USE (deduzir)
    """
    user_id = session['user_id']
    item_id = request.form.get('item_id')

    c = db.cursor()

    # 1. CHECK: Verifica saldo e estoque
    c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
    balance = c.fetchone()[0]

    c.execute('SELECT name, price, stock FROM items WHERE id = ?', (item_id,))
    item = c.fetchone()

    if not item or item[2] <= 0:
        session['flag'] = 'Item não disponível'
        return render_template_string('<script>location.href="/"</script>')

    item_name, price, stock = item

    if balance >= price:
        # DELAY ARTIFICIAL - facilita race! ⏱️
        time.sleep(0.01)

        # 2. USE: Deduz saldo e estoque
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, user_id))
        c.execute('UPDATE items SET stock = stock - 1 WHERE id = ?', (item_id,))
        c.execute('INSERT INTO purchases (user_id, item_id, timestamp) VALUES (?, ?, datetime("now"))',
                  (user_id, item_id))
        db.commit()

        # Verifica se comprou mais que deveria (double spending)
        c.execute('SELECT COUNT(*) FROM purchases WHERE user_id = ?', (user_id,))
        purchase_count = c.fetchone()[0]

        c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        new_balance = c.fetchone()[0]

        if new_balance < 0:
            session['flag'] = 'FLAG{race_double_spending} - Você comprou mais items do que seu saldo permitia!'
        elif purchase_count >= 2 and new_balance < 100:
            session['flag'] = 'FLAG{race_double_spending} - Double spending detectado!'

        return render_template_string('<script>location.href="/"</script>')
    else:
        session['flag'] = 'Saldo insuficiente'
        return render_template_string('<script>location.href="/"</script>')

@app.route('/apply_coupon', methods=['POST'])
@login_required
def apply_coupon():
    """
    VULNERÁVEL: Limit overrun em cupons
    Delay entre CHECK (usos) e USE (incrementar)
    """
    coupon_code = request.form.get('coupon_code')
    user_id = session['user_id']

    c = db.cursor()

    # 1. CHECK: Cupom válido e não excedeu limite?
    c.execute('SELECT discount, max_uses, current_uses FROM coupons WHERE code = ?', (coupon_code,))
    coupon = c.fetchone()

    if not coupon:
        session['flag'] = 'Cupom inválido'
        return render_template_string('<script>location.href="/"</script>')

    discount, max_uses, current_uses = coupon

    if current_uses < max_uses:
        # DELAY ARTIFICIAL ⏱️
        time.sleep(0.01)

        # 2. USE: Incrementa uso e aplica desconto
        c.execute('UPDATE coupons SET current_uses = current_uses + 1 WHERE code = ?', (coupon_code,))
        c.execute('UPDATE users SET balance = balance * ? WHERE id = ?',
                  (1 + discount / 100, user_id))
        db.commit()

        # Verifica se usou mais vezes que o permitido
        c.execute('SELECT current_uses FROM coupons WHERE code = ?', (coupon_code,))
        new_uses = c.fetchone()[0]

        if new_uses > max_uses:
            session['flag'] = f'FLAG{{race_limit_overrun}} - Você usou cupom {new_uses} vezes (limite: {max_uses})!'
        else:
            session['flag'] = f'Cupom aplicado! +{discount}% de crédito'

        return render_template_string('<script>location.href="/"</script>')
    else:
        session['flag'] = 'Cupom já foi usado'
        return render_template_string('<script>location.href="/"</script>')

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    """
    VULNERÁVEL: TOCTOU em transferências
    """
    from_user_id = session['user_id']
    to_username = request.form.get('to_user')
    amount = float(request.form.get('amount'))

    c = db.cursor()

    # Busca usuário destino
    c.execute('SELECT id FROM users WHERE username = ?', (to_username,))
    to_user = c.fetchone()

    if not to_user:
        session['flag'] = 'Usuário não encontrado'
        return render_template_string('<script>location.href="/"</script>')

    to_user_id = to_user[0]

    # 1. CHECK: Saldo suficiente?
    c.execute('SELECT balance FROM users WHERE id = ?', (from_user_id,))
    balance = c.fetchone()[0]

    if balance >= amount:
        # DELAY ⏱️
        time.sleep(0.01)

        # 2. USE: Transfere
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, from_user_id))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, to_user_id))
        db.commit()

        # Verifica se ficou negativo
        c.execute('SELECT balance FROM users WHERE id = ?', (from_user_id,))
        new_balance = c.fetchone()[0]

        if new_balance < 0:
            session['flag'] = f'FLAG{{race_toctou}} - Você transferiu ${amount} mas tinha ${balance}! Saldo: ${new_balance}'
        else:
            session['flag'] = f'Transferido ${amount} para {to_username}'

        return render_template_string('<script>location.href="/"</script>')
    else:
        session['flag'] = 'Saldo insuficiente'
        return render_template_string('<script>location.href="/"</script>')

if __name__ == '__main__':
    print('=' * 70)
    print('⏱️ Race Conditions - Basic Lab')
    print('=' * 70)
    print('🌐 URL: http://localhost:5110')
    print('📊 Dificuldade: 🟡 Intermediário')
    print('🎯 Pontos: 15')
    print('')
    print('⚠️  ATENÇÃO: Esta aplicação é INTENCIONALMENTE vulnerável!')
    print('   Delays artificiais facilitam exploitation.')
    print('')
    print('👥 Usuários de Teste:')
    print('  • alice / password123 (saldo: $100)')
    print('  • bob / password456 (saldo: $50)')
    print('')
    print('🚩 Flags:')
    print('  1. FLAG{race_limit_overrun} - Use cupom > 1 vez')
    print('  2. FLAG{race_double_spending} - Compre 2 items com $ para 1')
    print('  3. FLAG{race_toctou} - Transfira mais que o saldo')
    print('')
    print('💡 Exploração:')
    print('  • Use Python threading/asyncio')
    print('  • Burp Suite "Send group in parallel"')
    print('  • Bash + cURL com &')
    print('  • HTTP/2 multiplexing')
    print('')
    print('🎯 Delay artificial: 0.01s entre CHECK e USE')
    print('=' * 70)

    app.run(host='0.0.0.0', port=5110, debug=False, threaded=True)
