# Teoria Fundamental de SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: Varia de 🟢 Básica a 🔴 Avançada
**Bounty Médio**: $500 - $30,000 USD

---

## 📚 Índice

1. [Fundamentos Teóricos](#fundamentos-teóricos)
2. [Arquitetura de Processamento SQL](#arquitetura-de-processamento-sql)
3. [Por Que SQL Injection Existe](#por-que-sql-injection-existe)
4. [Teoria da Composição de Strings](#teoria-da-composição-de-strings)
5. [Separação de Dados e Código](#separação-de-dados-e-código)
6. [Análise de Complexidade](#análise-de-complexidade)

---

## 🔬 Fundamentos Teóricos

### O Que É SQL Injection em Essência?

**SQL Injection** não é apenas "inserir SQL malicioso". É fundamentalmente um problema de **confusão entre dados e código** que ocorre quando:

1. **Código SQL é construído dinamicamente** usando concatenação de strings
2. **Entrada do usuário é interpretada como sintaxe SQL** ao invés de dados literais
3. **Limites entre instruções e dados são violados**

### A Raiz do Problema: Linguagens de Dois Níveis

**Conceito de Metalinguagem:**

```
Nível 1: Linguagem Hospedeira (Host Language)
  → Python, PHP, Java, JavaScript, etc.
  → Código da aplicação

Nível 2: Linguagem Embarcada (Embedded Language)
  → SQL
  → Queries dinâmicas construídas na linguagem hospedeira
```

**O Problema:**

```python
# Linguagem hospedeira: Python
query = "SELECT * FROM users WHERE username = '" + user_input + "'"
#        ↑ String literal em Python                  ↑ String concat

# Problema: user_input pode ESCAPAR do contexto de dados
# e ser interpretado como CÓDIGO SQL
```

### Teoria de Gramáticas Formais

**SQL como Gramática Livre de Contexto (CFG):**

SQL é uma linguagem com gramática formal definida por regras de produção:

```
<query> ::= SELECT <columns> FROM <table> WHERE <condition>

<condition> ::= <expression> <operator> <value>
              | <condition> AND <condition>
              | <condition> OR <condition>
              | ( <condition> )

<value> ::= '<string>'
          | <number>
          | <identifier>
```

**Quando ocorre SQL Injection:**

O parser SQL não consegue distinguir entre:
- **Tokens de dados** (valores literais fornecidos pelo usuário)
- **Tokens de sintaxe** (palavras-chave SQL, operadores, delimitadores)

**Exemplo:**

```sql
-- Query pretendida (tokens esperados):
SELECT * FROM users WHERE username = 'admin'
--                                    ↑ STRING TOKEN ↑

-- Query com injection:
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
--                                    ↑ STRING TOKEN ↑  ↑ OR KEYWORD ↑  ↑ COMPARISON ↑
--                                    Tokens de SINTAXE injetados!
```

**O parser não sabe que `OR '1'='1'` deveria ser DADOS, interpreta como CÓDIGO.**

---

## ⚙️ Arquitetura de Processamento SQL

### Pipeline Completo de Execução de Query

Quando uma query SQL é executada, ela passa por múltiplas fases:

#### Fase 1: Lexical Analysis (Tokenização)

**Função:** Converte string SQL em tokens

```
Input: "SELECT * FROM users WHERE id = 1"

Tokens:
[SELECT] [*] [FROM] [users] [WHERE] [id] [=] [1]
  ↑keyword    ↑identifier       ↑identifier  ↑literal
```

**SQL Injection nesta fase:**

```sql
-- Input malicioso:
id = 1 OR 1=1

-- Tokens gerados:
[id] [=] [1] [OR] [1] [=] [1]
            ↑ OR keyword injetado!
```

**Por que funciona:**
- Lexer não distingue origem dos caracteres
- Trata toda a string de entrada uniformemente
- Não há contexto sobre "isso é dados do usuário"

#### Fase 2: Parsing (Análise Sintática)

**Função:** Constrói Abstract Syntax Tree (AST)

**Query normal:**
```
SELECT * FROM users WHERE id = 1
```

**AST:**
```
           SelectStatement
                 |
        +--------+--------+
        |                 |
   SelectClause      WhereClause
        |                 |
     AllColumns      Comparison
                          |
                    +-----+-----+
                    |           |
              Identifier('id')  Literal(1)
```

**Query com injection:**
```
SELECT * FROM users WHERE id = 1 OR 1=1
```

**AST modificado:**
```
           SelectStatement
                 |
        +--------+--------+
        |                 |
   SelectClause      WhereClause
        |                 |
     AllColumns      LogicalOR
                          |
                    +-----+-----+
                    |           |
               Comparison   Comparison
                    |           |
              [id = 1]      [1 = 1]
```

**Observação crítica:**
- AST está sintaticamente CORRETO
- Parser aceita porque é SQL válido
- Não há como o parser saber que `OR 1=1` não deveria existir

#### Fase 3: Semantic Analysis

**Função:** Valida tipos, resoluções de nomes, permissões

```
- Verifica se tabela 'users' existe
- Verifica se coluna 'id' existe
- Verifica tipos: id INT, comparação com INT
- Verifica permissões: usuário pode SELECT em users?
```

**SQL Injection nesta fase:**
- Análise semântica NÃO detecta injection
- Query é semanticamente válida
- `OR 1=1` é uma condição booleana perfeitamente válida

#### Fase 4: Query Optimization

**Função:** Gera plano de execução eficiente

**Query normal:**
```sql
SELECT * FROM users WHERE id = 123
```

**Plano de execução:**
```
1. Index seek on users.id where id = 123
2. Return row
```

**Query com injection:**
```sql
SELECT * FROM users WHERE id = 123 OR 1=1
```

**Plano de execução:**
```
1. Avalia: id = 123 OR 1=1
2. Simplifica: TRUE (porque 1=1 sempre é TRUE)
3. Full table scan (não pode usar índice)
4. Retorna TODAS as linhas
```

**Por que o otimizador não detecta:**
- `OR 1=1` é logicamente equivalente a TRUE
- Otimizador pode até "otimizar" para table scan direto
- Não há conceito de "cláusula suspeita"

#### Fase 5: Execution

**Função:** Executa o plano, acessa dados, retorna resultados

```
1. Adquire locks necessários
2. Lê páginas de dados
3. Aplica filtros (WHERE)
4. Constrói result set
5. Retorna para aplicação
```

**SQL Injection nesta fase:**
- Execução é completamente legítima do ponto de vista do DB
- Database retorna resultados conforme solicitado
- Não há violação de regras do banco de dados

### Por Que Cada Fase Falha em Detectar

**Análise de Falha Sistêmica:**

| Fase | Por Que Não Detecta Injection |
|------|-------------------------------|
| **Lexer** | Não tem contexto sobre origem dos dados |
| **Parser** | SQL injetado é sintaticamente válido |
| **Semantic** | Query é semanticamente correta |
| **Optimizer** | Query é logicamente válida (até otimizável) |
| **Executor** | Apenas executa o plano aprovado |

**Conclusão:** SQL Injection é **invisível** para o database engine porque a query final é **perfeitamente válida** em todos os níveis.

---

## 🧩 Por Que SQL Injection Existe

### 1. Decisões de Design Histórico

**Era 1990s - Simplicidade de Concatenação:**

```php
// PHP 3/4 era (1997-2000)
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($query);
```

**Por que isso foi permitido:**
- Simplicidade: desenvolvedores entendiam strings
- Performance: sem overhead de parsing adicional
- Flexibilidade: queries completamente dinâmicas
- Não havia cultura de segurança forte

### 2. Limitações de String Escaping

**Tentativa de "Escape" - Por Que Falha:**

```php
// Tentativa ingênua de segurança
$safe = addslashes($_GET['id']);  // Adiciona \ antes de '
$query = "SELECT * FROM users WHERE id = '$safe'";
```

**Por que isso não é suficiente:**

**Problema 1: Charset Attacks**
```php
$id = "\xbf\x27 OR 1=1 --";  // UTF-8: ¿' OR 1=1 --
$escaped = addslashes($id);  // \xbf\x5c\x27 OR 1=1 --
// Em alguns charsets, \xbf\x5c forma um único caractere
// Resultado: [char]' OR 1=1 --
```

**Problema 2: Context-Dependent Escaping**
```sql
-- Contexto 1: String literal
SELECT * FROM users WHERE name = 'John\'s'  -- \' funciona

-- Contexto 2: Identificador
SELECT * FROM users WHERE `name` = 'value'  -- ` é o escape
-- addslashes não ajuda aqui!

-- Contexto 3: Numérico (sem aspas)
SELECT * FROM users WHERE id = 1 OR 1=1  -- Sem string para escapar!
```

### 3. O Problema Fundamental: Mixing Code and Data

**Teoria da Computação - Princípio da Separação:**

Em teoria da computação, é um **anti-pattern** misturar:
- **Código** (instruções, lógica de controle)
- **Dados** (valores, conteúdo)

**Por que isso é problemático:**

```
Program = Code + Data

Quando Code contém Data dinamicamente:
  Program = Code + (CodeFragments + Data)
                      ↑ Data pode se tornar Code!

Violação: Data pode alterar o fluxo de controle de Code
```

**Exemplo abstrato:**

```python
# Programa = Código + Dados
def process(user_input):  # user_input = DADOS
    code = f"result = 1 + {user_input}"  # MISTURA
    eval(code)  # EXECUTA
    return result

# Uso normal:
process("5")  # Código: result = 1 + 5, Resultado: 6

# Injection:
process("5; import os; os.system('rm -rf /')")
# Código: result = 1 + 5; import os; os.system('rm -rf /')
#         ↑ Dados se tornaram código executável!
```

### 4. SQL Não Tem Tipos de "Tainted Data"

**Linguagens com Taint Tracking:**

Algumas linguagens modernas marcam dados não confiáveis:

```ruby
# Ruby (com taint mode)
user_input = gets  # Automatically tainted
user_input.tainted?  # => true

system("ls #{user_input}")  # ERRO: tainted data in system call
```

**SQL não tem isso:**

```sql
-- SQL não distingue:
SELECT * FROM users WHERE id = 1  -- Literal codificado
SELECT * FROM users WHERE id = ?  -- Parâmetro (seguro)
SELECT * FROM users WHERE id = <user_input>  -- Entrada (inseguro)

-- Todos são tratados IGUALMENTE após parsing
```

---

## 📐 Teoria da Composição de Strings

### Composição vs. Parametrização

**Modelo Matemático:**

**Composição (Insegura):**
```
Query(input) = Template ⊕ input

Onde ⊕ = concatenação de strings

Propriedade: Template ⊕ input ∈ SQL_Language
             ↑ Resultado pode ser QUALQUER string SQL válida
```

**Parametrização (Segura):**
```
Query(input) = Template ⊗ [input]

Onde ⊗ = substituição parametrizada
      [input] = input tratado como valor atômico

Propriedade: Template ⊗ [input] ∈ SQL_Safe_Subset
             ↑ Resultado é constrangido a um subset seguro
```

### Análise de Segurança Formal

**Definição de Segurança:**

Uma query é **segura** se e somente se:

```
∀ input ∈ User_Input:
  Semantics(Query(input)) = Intended_Semantics

Onde:
  Semantics = função que mapeia query para seu significado
  Intended_Semantics = comportamento esperado pelo desenvolvedor
```

**Composição por concatenação VIOLA isso:**

```
Exemplo:
  Template = "SELECT * FROM users WHERE id = "
  Intended_Semantics = "Retornar usuário com ID específico"

  input₁ = "123"
  Semantics(Template + input₁) = "Retornar user 123"  ✓

  input₂ = "123 OR 1=1"
  Semantics(Template + input₂) = "Retornar TODOS os usuários"  ✗
                                  ↑ Diferente de Intended_Semantics!
```

**Parametrização GARANTE isso:**

```
Template = "SELECT * FROM users WHERE id = ?"

∀ input: Semantics(Template[input]) = "Retornar user com ID = valor"
                                       ↑ SEMPRE tem mesma semântica!
```

---

## 🔐 Separação de Dados e Código

### O Princípio de Homoiconicidade

**Homoiconicidade** = Código e dados têm a mesma representação

**Em SQL (problema):**
```sql
-- Código:
SELECT * FROM users WHERE id = 1 OR 1=1

-- Dados:
"1 OR 1=1"

-- Ambos são representados como STRINGS!
-- Parser não consegue distinguir origem!
```

**Solução: Prepared Statements**

```
Separação em nível de protocolo:

1. Cliente envia: "SELECT * FROM users WHERE id = ?"
   ↑ Template de código (parsed uma vez)

2. Database faz parsing, cria plano de execução

3. Cliente envia: [123]
   ↑ Dados PUROS (nunca parsed)

4. Database substitui ? por 123 como VALOR LITERAL
   ↑ Não re-parsing, apenas substituição de valor
```

**Por que isso funciona:**

```
Query = Parse(Template) + Bind(Parameters)

Parse(Template):
  → Cria AST FIXO
  → Define estrutura da query
  → Identifica placeholders (?)

Bind(Parameters):
  → Substitui ? por valores
  → NÃO modifica AST
  → Parâmetros são SEMPRE valores literais

Resultado: AST é imutável, estrutura é garantida
```

### Análise de Fluxo de Dados

**Taint Analysis (Análise de Contaminação):**

```
Source: user_input (TAINTED)
Sink: SQL query execution

Safe flow:
  user_input → Sanitization → Query  ✓

Unsafe flow:
  user_input → String concatenation → Query  ✗
               ↑ Taint propagates!
```

**Grafo de Dependência:**

```
query_string = "SELECT * FROM users WHERE id = " + user_input
                ↑                                    ↑
            CLEAN (code)                        TAINTED (data)
                |                                    |
                +----------> Concatenation <---------+
                                    |
                               TAINTED (!)
                                    |
                            SQL Execution
                                    ↓
                           Security Violation
```

---

## 📊 Análise de Complexidade

### Complexidade de Detecção

**Problema:** Detectar SQL Injection em tempo de execução

**Input:** String SQL construída dinamicamente
**Output:** SAFE ou UNSAFE

**Complexidade:** **Indecidível** em caso geral

**Por quê:**

```
Problema reduz a: "Esta query alterará a semântica pretendida?"

Semântica pretendida = Estado mental do desenvolvedor
                      ↑ Não formalizável computacionalmente!

Teorema: Não existe algoritmo que, dada uma query arbitrária,
         determine se ela viola a intenção original.
```

**Implicação:** Não é possível criar um firewall perfeito que detecte todas as SQL injections baseado apenas na query final.

### Complexidade de Exploração

**Blind Boolean SQLi - Complexidade de Extração:**

**Problema:** Extrair string de comprimento `n` usando boolean queries

**Método 1: Brute Force**
```
Charset: a-z, A-Z, 0-9 = 62 caracteres
Comprimento: n
Tentativas: 62ⁿ (exponencial)

Exemplo: password de 10 chars
  62¹⁰ = 839,299,365,868,340,224 tentativas
  Impraticável!
```

**Método 2: Binary Search**
```
ASCII range: 32-126 = 94 caracteres
Bits: log₂(94) ≈ 7 bits por caractere
Tentativas por char: 7
Total para n chars: 7n (linear)

Exemplo: password de 10 chars
  7 × 10 = 70 tentativas
  Praticável! ✓
```

**Análise de Complexidade:**

| Método | Complexidade | Tentativas (n=10) | Tempo (1 req/sec) |
|--------|--------------|-------------------|-------------------|
| Brute Force | O(c^n) | 62¹⁰ | ~26 milhões de anos |
| Binary Search | O(n log c) | 70 | 70 segundos |
| Parallel Binary (10 threads) | O(n log c) | 70 | 7 segundos |

**Algoritmo Ótimo:**

```python
def extract_char_binary(position):
    """
    Extrai caractere na posição usando busca binária.
    Complexidade: O(log₂(charset_size))
    """
    low, high = 32, 126  # ASCII range

    while low < high:
        mid = (low + high) // 2

        # Query: Is char > mid?
        if is_true(f"ASCII(SUBSTR(password, {position}, 1)) > {mid}"):
            low = mid + 1
        else:
            high = mid

    return chr(low)

# Complexidade total: O(n × log₂(c))
# Onde n = comprimento da string
#      c = tamanho do charset
```

**Teorema:** Binary search é **ótimo** para boolean blind SQLi, pois:
- Cada query fornece 1 bit de informação
- São necessários log₂(c) bits para identificar um caractere entre c possibilidades
- Portanto, log₂(c) queries é o **limite inferior** (lower bound)

---

## 🧮 Teoria da Informação Aplicada

### Entropia e Vazamento de Informação

**Blind SQLi como Canal de Informação:**

```
Shannon's Information Theory:

I(X;Y) = H(X) - H(X|Y)

Onde:
  I(X;Y) = informação mútua (bits vazados)
  H(X) = entropia de X (senha)
  H(X|Y) = entropia condicional
```

**Aplicação:**

```
X = caractere da senha (94 possibilidades)
Y = resposta da query (TRUE/FALSE)

H(X) = log₂(94) ≈ 6.55 bits

Cada query boolean:
  H(Y) = 1 bit (TRUE ou FALSE)

Information leak por query:
  I(X;Y) ≈ 1 bit (ideal)

Queries necessárias:
  H(X) / I(X;Y) = 6.55 / 1 ≈ 7 queries
```

**Análise de Eficiência:**

| Técnica | Bits/Query | Queries/Char | Eficiência |
|---------|------------|--------------|------------|
| Binary Search | ~1.0 | 7 | 100% (ótimo) |
| Ternary Search | ~1.5 | 5 | >100% (impossível na prática) |
| Linear Search | ~0.1 | 94 | 14% |
| Time-based (ruidoso) | ~0.7 | 10 | 70% |

**Conclusão:** Binary search extrai informação na taxa máxima teoricamente possível para um canal boolean.

---

## 🔄 Modelo de Ameaça (Threat Model)

### Classificação de Atacantes

**Nível 1: Script Kiddie**
```
Capacidade: Usa ferramentas prontas (SQLMap)
Conhecimento: Básico de SQL
Detecção: Fácil (alto volume de requests, padrões conhecidos)
Defesa: WAF com regras básicas
```

**Nível 2: Desenvolvedor Experiente**
```
Capacidade: Entende SQL, escreve queries customizadas
Conhecimento: Intermediário (sabe bypassar filtros simples)
Detecção: Moderada
Defesa: Input validation + prepared statements
```

**Nível 3: Security Researcher**
```
Capacidade: Conhece internals de databases, timing attacks
Conhecimento: Avançado (blind techniques, second-order)
Detecção: Difícil (baixo volume, stealth)
Defesa: Defense-in-depth, monitoring, rate limiting
```

**Nível 4: APT (Advanced Persistent Threat)**
```
Capacidade: 0-days em databases, custom tools
Conhecimento: Expert (timing side-channels, cache attacks)
Detecção: Muito difícil (mimics normal traffic)
Defesa: Segurança perfeita (prepared statements) + monitoring avançado
```

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
