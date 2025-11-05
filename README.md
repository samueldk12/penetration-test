# Penetration Test Suite v2.0.0

**Sistema Completo de Penetration Testing** com 18+ plugins integrados, suporte Python + JavaScript, módulo OSINT e relatórios avançados.

---

## 🚀 Quick Start

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Inicializar configuração
./penetration-test.py config --init

# 3. Ver plugins disponíveis
./penetration-test.py plugins -v

# 4. Executar scan completo
./penetration-test.py scan example.com --all-plugins --complete --verbose
```

---

## 📖 Documentação Completa

**[Ver Manual Completo →](CLI_MANUAL.md)**

O manual contém:
- 📚 Instalação e Configuração
- 🎯 Todos os Comandos Detalhados  
- 🔌 Lista de Plugins
- 💡 Exemplos de Uso
- 🔧 Troubleshooting
- 🟨 Criação de Plugins JS

---

## ⚡ Comandos Principais

| Comando | Descrição |
|---------|-----------|
| `scan <target> --all-plugins -v` | Executa todos os plugins |
| `osint <target> --deep` | Investigação OSINT |
| `report --type comprehensive` | Gera relatórios |
| `plugins -v` | Lista plugins disponíveis |
| `stats` | Estatísticas do banco |

---

## 🔌 Plugins (18+)

**Recon (8)**: nmap, nuclei, ffuf, katana, subdominator, dnsbruter, cert_transparency, search_engine_dorking

**Vuln Scan (10)**: nikto, dalfox, xss_scanner, xss_detector(JS), sqli, ssrf, lfi, open_redirect, sensitive_files, cloud_vuln_tester

---

## 📊 Features

- ✅ 18+ plugins (Python + JavaScript)
- ✅ Módulo OSINT completo
- ✅ Relatórios em JSON/HTML/Markdown
- ✅ Detecção de API keys (AWS, GCP, Azure, GitHub, etc)
- ✅ Execução paralela de plugins
- ✅ Configuração via YAML
- ✅ Logging verboso
- ✅ Arquitetura modular

---

## 📝 License

Educational and authorized testing only.

**Version**: 2.0.0 | [Full Manual](CLI_MANUAL.md) | [GitHub](https://github.com/samueldk12/penetration-test)
