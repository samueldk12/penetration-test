# 📝 SQL Injection - Exercícios Práticos

## 🎯 Instruções

Complete cada exercício e documente suas descobertas. Cada exercício tem pontuação que contribui para seu total.

**Formato de entrega**:
```markdown
### Exercício X
**Payload**: `seu payload aqui`
**Resultado**: Descrição do que aconteceu
**Flag**: FLAG{...} (se aplicável)
**Screenshot**: (opcional)
```

---

## 🟢 Nível Básico (Basic App)

### Exercício 1: First Blood (5 pts)

**Objetivo**: Gere um erro SQL intencionalmente

**Endpoint**: http://localhost:5010/login

**Tarefa**: Insira um payload que cause erro SQL e copie a mensagem de erro completa.

**Dicas**:
- Tente aspas simples
- Observe a mensagem de erro
- A mensagem revela a estrutura da query?

---

### Exercício 2: Authentication Bypass (10 pts)

**Objetivo**: Faça login como admin sem saber a senha

**Endpoint**: http://localhost:5010/login

**Tarefa**: Encontre pelo menos 3 payloads diferentes que permitam login como admin.

**Dicas**:
- Use comentários (-- ou #)
- Tente OR 1=1
- Teste variações

**Payloads esperados**:
1. `________________________________`
2. `________________________________`
3. `________________________________`

---

### Exercício 3: Column Discovery (10 pts)

**Objetivo**: Descubra quantas colunas a query SELECT retorna

**Endpoint**: http://localhost:5010/search

**Tarefa**: Use ORDER BY ou UNION SELECT para descobrir o número exato de colunas.

**Número de colunas**: `________`

**Método usado**: `________________________________`

---

### Exercício 4: Database Enumeration (15 pts)

**Objetivo**: Liste todas as tabelas do banco de dados

**Endpoint**: http://localhost:5010/search

**Tarefa**: Use UNION SELECT para extrair nomes de todas as tabelas.

**Payload UNION**: `________________________________`

**Tabelas encontradas**:
1. `________________________________`
2. `________________________________`
3. `________________________________` (se houver mais)

---

### Exercício 5: Secret Extraction (20 pts)

**Objetivo**: Extraia todos os dados da tabela `secrets`

**Endpoint**: http://localhost:5010/search

**Tarefas**:
1. Descubra as colunas da tabela `secrets`
2. Extraia todos os registros
3. Encontre todas as flags escondidas

**Estrutura da tabela**: `________________________________`

**Dados extraídos**: (cole aqui)

**Flags encontradas**:
- `FLAG{_______________}`
- `FLAG{_______________}`
- `FLAG{_______________}`

---

### Exercício 6: Error-Based Extraction (15 pts)

**Objetivo**: Use erros SQL para extrair dados

**Endpoint**: http://localhost:5010/search

**Tarefa**: Force um erro que revele o nome da primeira tabela usando CAST ou conversão de tipo.

**Payload**: `________________________________`

**Informação extraída**: `________________________________`

---

## 🟡 Nível Intermediário (Intermediate App)

### Exercício 7: WAF Detection (10 pts)

**Objetivo**: Identifique quais palavras o WAF está bloqueando

**Endpoint**: http://localhost:5011/search

**Tarefa**: Teste diferentes payloads e documente quais palavras são bloqueadas.

**Palavras bloqueadas**:
- `________________________________`
- `________________________________`
- `________________________________`
- `________________________________`

---

### Exercício 8: WAF Bypass - Case Variation (15 pts)

**Objetivo**: Bypasse o WAF usando variação de case

**Endpoint**: http://localhost:5011/login

**Tarefa**: Login como admin usando case variation para bypassar WAF.

**Payload que funcionou**: `________________________________`

**Flag**: `FLAG{_______________}`

---

### Exercício 9: WAF Bypass - Comments (15 pts)

**Objetivo**: Bypasse o WAF usando comentários inline

**Endpoint**: http://localhost:5011/search

**Tarefa**: Execute uma UNION SELECT query usando comentários /* */ para bypassar filtros.

**Payload**: `________________________________`

**Dados extraídos**: `________________________________`

---

### Exercício 10: Multiple Injection Points (20 pts)

**Objetivo**: Identifique TODOS os pontos de injeção na aplicação

**Tarefa**: Teste todos os endpoints e liste os vulneráveis.

**Endpoints vulneráveis**:
1. `/login` - Parâmetro: `________________________________`
2. `/search` - Parâmetro: `________________________________`
3. `/products` - Parâmetro: `________________________________`
4. `/stats` - Parâmetro: `________________________________`
5. Outros: `________________________________`

---

### Exercício 11: Payment Data Extraction (25 pts)

**Objetivo**: Extraia dados de cartão de crédito da tabela `payments`

**Tarefa**:
1. Faça login como admin
2. Acesse /admin OU extraia via SQLi
3. Documente todos os cartões encontrados

**Método usado**: `________________________________`

**Cartões extraídos**:
- `________________________________`
- `________________________________`
- `________________________________`

**Flag**: `FLAG{_______________}`

---

### Exercício 12: Stored SQLi (30 pts)

**Objetivo**: Explore Stored SQL Injection em reviews

**Tarefa**:
1. Envie um review com payload SQL
2. Trigger a execução visitando a página
3. Extraia dados de outros usuários

**Payload do review**: `________________________________`

**URL que triggera**: `________________________________`

**Dados extraídos**: `________________________________`

**Flag**: `FLAG{_______________}`

---

### Exercício 13: Filter Evasion Chaining (25 pts)

**Objetivo**: Combine múltiplas técnicas de bypass

**Tarefa**: Crie um payload que use:
- Case variation
- Comentários inline
- Encoding (se possível)
- Espaços alternativos

**Payload final**: `________________________________`

**Técnicas usadas**:
1. `________________________________`
2. `________________________________`
3. `________________________________`

---

## 🔴 Nível Avançado (Desafios)

### Exercício 14: Blind Boolean Extraction (40 pts)

**Objetivo**: Implemente extração de dados usando Boolean-based Blind SQLi

**Tarefa**: Escreva script Python que extraia a senha do admin character por character.

**Código** (cole aqui ou anexe arquivo):
```python
# Seu código aqui
```

**Senha extraída**: `________________________________`

**Tempo de execução**: `__________ segundos`

---

### Exercício 15: Automated Exploitation (50 pts)

**Objetivo**: Crie ferramenta automatizada de SQLi

**Tarefa**: Desenvolva script que:
1. Detecta vulnerabilidade
2. Descobre número de colunas
3. Lista todas as tabelas
4. Extrai dados de tabela especificada

**Código** (cole ou anexe):
```python
# Seu código aqui
```

**Output do script**:
```
[cole output aqui]
```

---

### Exercício 16: Second-Order SQLi (45 pts)

**Objetivo**: Descubra e explore Second-Order SQLi

**Tarefa**:
1. Identifique onde input é armazenado
2. Identifique onde é usado sem sanitização
3. Crie payload que explore esta vulnerabilidade

**Endpoint de injection**: `________________________________`

**Endpoint de trigger**: `________________________________`

**Payload**: `________________________________`

**Resultado**: `________________________________`

---

### Exercício 17: SQLi to RCE (60 pts)

**Objetivo**: Tente obter Remote Code Execution via SQLi

**Tarefa**: Pesquise e tente técnicas para RCE:
- Escrever arquivo (INTO OUTFILE)
- Load file
- Comandos SQL específicos do DBMS

**Nota**: Como estamos em SQLite, RCE direto é limitado. Documente tentativas.

**Tentativas**:
1. `________________________________`
2. `________________________________`

**Resultado**: `________________________________`

---

### Exercício 18: WAF Bypass - Advanced (40 pts)

**Objetivo**: Bypasse WAF usando técnicas avançadas

**Tarefa**: Use pelo menos 3 das seguintes técnicas:
- URL encoding
- Double encoding
- Unicode
- Null bytes
- HTTP Parameter Pollution
- Charset manipulation

**Payloads**:
1. Técnica: `____________` | Payload: `________________________________`
2. Técnica: `____________` | Payload: `________________________________`
3. Técnica: `____________` | Payload: `________________________________`

---

## 🏆 Desafios Criativos (Bônus)

### Desafio 1: Polyglot Payload (50 pts)

**Objetivo**: Crie payload que funcione em múltiplos contextos

**Tarefa**: Desenvolva payload SQL que funcione em:
- GET parameter
- POST parameter
- JSON body
- Cookie

**Payload**: `________________________________`

---

### Desafio 2: Mini CTF (100 pts)

**Objetivo**: Complete uma chain completa de exploração

**Cenário**: Você tem acesso apenas ao endpoint /search. A partir dele:
1. Descubra todas as tabelas
2. Encontre credenciais admin
3. Acesse painel admin
4. Extraia dados sensíveis
5. Documente cada passo

**Relatório** (formato livre):
```
[Seu relatório aqui]
```

---

### Desafio 3: Tool Development (150 pts)

**Objetivo**: Crie ferramenta completa de SQLi exploitation

**Requisitos**:
- Interface CLI amigável
- Detecção automática de vulnerabilidade
- Suporte para UNION e Blind SQLi
- Exportação de dados (CSV/JSON)
- WAF bypass integrado
- Logging detalhado

**Repositório GitHub**: `________________________________`

**Demo**: (vídeo ou GIF)

---

## 📊 Sistema de Pontuação

| Nível | Exercícios | Pontos Possíveis |
|-------|------------|------------------|
| 🟢 Básico | 1-6 | 75 pts |
| 🟡 Intermediário | 7-13 | 165 pts |
| 🔴 Avançado | 14-18 | 235 pts |
| 🏆 Bônus | 1-3 | 300 pts |
| **TOTAL** | **21 exercícios** | **775 pts** |

### Classificação

- **0-100 pts**: 🥉 Iniciante
- **101-250 pts**: 🥈 Intermediário
- **251-450 pts**: 🥇 Avançado
- **451-600 pts**: 🏆 Expert
- **601+ pts**: 👑 Master

---

## 📋 Template de Resposta

Copie e preencha:

```markdown
# Respostas - SQL Injection Lab
**Nome**: Seu Nome
**Data**: DD/MM/YYYY
**Pontuação**: ___ / 775

---

## 🟢 Nível Básico

### Exercício 1: First Blood (5 pts)
**Payload**:
**Resultado**:
**Completado**: [ ]

### Exercício 2: Authentication Bypass (10 pts)
**Payloads**:
1.
2.
3.
**Completado**: [ ]

[Continue para todos os exercícios...]

---

## 📊 Resumo

**Total de exercícios completados**: ___ / 21
**Pontuação final**: ___ / 775
**Classificação alcançada**: ___________

**Tempo total gasto**: __________ horas

**Lições aprendidas**:
1.
2.
3.

**Dificuldades encontradas**:
1.
2.

**Próximos passos**:
1.
2.
```

---

## 🎓 Recursos para Ajuda

### Se estiver travado:

1. **Revise a teoria**: [README.md](README.md)
2. **Veja exemplos**: [exploits.md](exploits.md)
3. **Consulte cheat sheets**:
   - [PortSwigger SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
   - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

### Ferramentas úteis:

- **Burp Suite** - Interceptar requests
- **SQLMap** - Automação (só use depois de tentar manualmente!)
- **CyberChef** - Encoding/decoding

---

## ✅ Submissão

Quando completar, salve suas respostas em:
```
my_solutions/01-sql-injection-solutions.md
```

Opcional: Compartilhe no GitHub ou LinkedIn com #SQLiLab

---

**Boa sorte! 💉🎯**

**Voltar**: [README.md](README.md) | **Exploits**: [exploits.md](exploits.md)
