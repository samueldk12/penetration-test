# Interactive Selenium Pentester

Plugin interativo de testes de segurança com Selenium usando hotkeys.

## Recursos

✅ **Testes com Hotkeys:**
- `Ctrl + I` - SQL Injection (11 payloads)
- `Ctrl + X` - XSS (10 payloads)
- `Ctrl + L` - LFI (6 payloads)
- `Ctrl + C` - Console JavaScript Test
- `Ctrl + Q` - Sair

✅ **Feedback Visual:**
- Notificações coloridas no browser
- Highlight de elementos testados
- Alertas em tempo real

✅ **Análise Automática:**
- Detecção de erros SQL
- Reflexão de payloads XSS
- Indicadores de LFI

## Instalação

```bash
pip install selenium pynput beautifulsoup4
```

## Uso

```bash
# Básico
python3 selenium_interactive.py https://example.com

# Com opções
python3 selenium_interactive.py https://example.com '{
    "browser": "chrome",
    "proxy_enabled": false,
    "console_mode": true
}'
```

## Fluxo de Trabalho

1. Execute o plugin - browser abrirá automaticamente
2. Navegue pelo site normalmente
3. Clique em um input que deseja testar
4. Pressione a hotkey correspondente (Ctrl+I, Ctrl+X, Ctrl+L)
5. Aguarde os testes automáticos
6. Veja o resultado nas notificações

## Exemplo Prático

```
1. python3 selenium_interactive.py https://vulnerable-site.com
2. [Browser abre]
3. Navegar até /login
4. Clicar no campo "username"
5. Pressionar Ctrl+I
6. [Plugin testa 11 payloads de SQL Injection]
7. Notificação: "⚠️ SQL Injection vulnerability detected!"
```

## Payloads

### SQL Injection
```
' OR '1'='1
' OR '1'='1' --
" OR "1"="1
admin' --
... (11 total)
```

### XSS
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
... (10 total)
```

### LFI
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
.... (6 total)
```

## Integração com Proxy

```python
options = {
    "proxy_enabled": true,
    "proxy_port": 8888
}
```

Todo o tráfego passará pelo proxy para análise.

## Console Mode

Com `console_mode: true`, o plugin pode executar testes JavaScript via console:

```javascript
// Teste fetch API
fetch('/api/users').then(r => r.json())

// Verificar headers
Object.entries(response.headers)
```

## Personalização

### Adicionar Novos Payloads

```python
self.sql_payloads.append("seu_payload_aqui")
self.xss_payloads.append("<seu>payload</aqui>")
```

### Adicionar Nova Hotkey

```python
# Em on_press()
elif key.char == 't':  # Ctrl+T
    self.testing_in_progress = True
    threading.Thread(target=self.handle_custom_test).start()

# Implementar handle_custom_test()
def handle_custom_test(self):
    element = self.driver.switch_to.active_element
    # Sua lógica aqui
```

## Output

Resultados salvos em JSON:

```json
{
  "target": "https://example.com",
  "tests_performed": [
    {
      "type": "sql_injection",
      "element": "username",
      "results": [...]
    }
  ],
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "high",
      "payload": "' OR '1'='1",
      "url": "https://example.com/login",
      "element": "username"
    }
  ]
}
```

## Dicas

- Use em sites de teste (DVWA, bWAPP)
- Configure delay entre testes se necessário
- Salve screenshots habilitando opção `screenshot`
- Combine com proxy para análise completa

## Troubleshooting

**Hotkeys não funcionam:**
```bash
# Linux: instalar python3-xlib
sudo apt-get install python3-xlib
```

**Browser não abre:**
```bash
# Verificar se WebDriver está no PATH
which chromedriver
```

**Testes muito lentos:**
```python
# Reduzir delay
time.sleep(0.2)  # em vez de 0.5
```

## Aviso

⚠️ Use apenas em ambientes autorizados. Testes não autorizados são ilegais.
