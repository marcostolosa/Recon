# ReconForge v2 — Pipeline de Reconhecimento para Bug Bounty

Framework de reconhecimento modular, assíncrono e orientado a escopo estrito em Python 3, projetado para transformar um único domínio em um inventário priorizado de superfície de ataque, reduzindo ruído e protegendo contra requisições destrutivas.

---

## 🎯 Arquitetura e Filosofia

ReconForge v2 substitui pipelines legados frágeis de bash por um motor assíncrono robusto (`asyncio` + `httpx` + `sqlite3`), garantindo:

```
[Domínio + Regras de Escopo]
        │
        ├── DNS & Certificate Transparency (crt.sh, CertSpotter, Subfinder, Amass)
        ├── Descoberta Histórica (gau, Wayback)
        ├── Crawling Inteligente (Katana, JSLuice, Headless Browser)
        │
        ▼
[Normalização & Deduplicação (SQLite WAL)]
        │
        ├── Extração de Segredos & Sourcemaps (Gitleaks, TruffleHog, Regex)
        ├── Fuzzing Contextual Controlado (Orçamento próprio / ffuf)
        └── Scanners Direcionados (Nuclei, Dalfox v3, SQLMap - Opt-in)
        │
        ▼
[Artefatos, Priorização & Evidências] (priority.csv, http.jsonl, state.sqlite)
```

---

## ⚡ Diferenciais da Versão 2

| Capacidade | Implementação na v2 |
| :--- | :--- |
| **Persistência e Retomada** | SQLite em modo WAL com deduplicação atômica, histórico de fontes (`url_sources`) e resume seguro. |
| **Proteção de Escopo Estrito** | Normalização IDNA/RFC, checagem recursiva de subdomínios, bloqueio de portas arbitrárias e descarte de OOS. |
| **Segurança Operacional** | Heurística anti-destrutiva (`UNSAFE_GET` para rotas como `/logout`, `/delete`), anti-SSRF para redes privadas. |
| **Rate Limiting Centralizado** | Controle de requisições (`Throttle`) com backoff automático em 429/503 e teto global (`--max-requests`). |
| **Análise Profunda de JS & APIs** | Extração de chamadas relativas, endpoints em schemas OpenAPI/Swagger, sourcemaps e fingerprints de credenciais (SHA-256). |
| **Renderização Dinâmica** | Suporte integrado opcional a Chromium/Playwright com interceptação de rotas e monitoramento de requests DOM. |
| **Scanners Direcionados** | Integração opt-in e em lote com Nuclei, Dalfox v3 (`dalfox scan`) e SQLMap apenas para endpoints relevantes. |

---

## 📦 Instalação

### Requisitos
- **Python 3.10+** (Testado em Python 3.11, 3.12 e 3.14 no Kali, Debian/Ubuntu, macOS e Windows).

```bash
# 1. Clone o repositório
git clone https://github.com/marcostolosa/Recon.git
cd Recon/

# 2. Crie e ative o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate  # No Windows: .venv\Scripts\activate

# 3. Instale as dependências Python
pip install -r requirements.txt

# 4. (Opcional) Instale o suporte a navegador headless
playwright install chromium
```

> **Ferramentas externas opcionais:** `subfinder`, `amass`, `gau`, `katana`, `ffuf`, `nuclei`, `dalfox`, `sqlmap`, `gitleaks`, `trufflehog`.
> Se alguma ferramenta externa não estiver no `PATH`, o ReconForge apenas registra um aviso e prossegue sem quebrar a execução.

---

## 🚀 Como Usar

### 1. Reconhecimento Passivo Estrito
Consulta fontes públicas de Certificados (CT) e coletores passivos sem enviar tráfego ativo:
```bash
python reconforge.py example.com --subdomains --passive-only --out runs/example-passive
```

### 2. Reconhecimento Ativo Completo Autorizado
Executa descoberta, crawling iterativo, extração profunda de JS e orçamento de fuzzing:
```bash
python reconforge.py example.com \
  --subdomains \
  --exclude staging.example.com \
  --exclude-path /logout \
  --exclude-path /billing \
  --katana \
  --jsluice \
  --fuzz \
  --rate 3 \
  --concurrency 5 \
  --max-hosts 300 \
  --max-probes 4000 \
  --max-requests 6000 \
  --out runs/example-full
```

### 3. Cabeçalho de Identificação para Bug Bounty
Programas no HackerOne e Bugcrowd frequentemente exigem headers de identificação:
```bash
python reconforge.py example.com --subdomains \
  -H "X-Bug-Bounty: hackerone-username" \
  -H "Contact: researcher@security.org" \
  --out runs/example-id
```

### 4. Execução de Scanners Direcionados (Opt-in)
Dispara testes focados em endpoints previamente validados e filtrados:
```bash
python reconforge.py example.com --subdomains \
  --scanners nuclei dalfox \
  --nuclei-tags exposure,misconfig \
  --scan-limit 25 \
  --out runs/example-scanners
```

### 5. Retomada de Sessão (Resume)
Reutilize o mesmo diretório `--out` e configurações de escopo. As URLs já verificadas não serão requisitadas novamente:
```bash
python reconforge.py example.com --subdomains --out runs/example-full
```

---

## 📁 Artefatos Gerados

Todas as evidências são estruturadas no diretório de saída:

- `state.sqlite`: Base relacional completa com inventário, estado de fila, status HTTP e logs de execução.
- `priority.csv`: Fila ordenada por criticidade e probabilidade de vulnerabilidade com identificação de Soft-404.
- `subdomains.txt`: Lista limpa e deduplicada de subdomínios in-scope.
- `urls.txt`: Todos os endpoints normalizados em escopo.
- `alive.txt`: Endpoints com retorno HTTP 2xx e 3xx.
- `parameterized.txt`: URLs com query strings prontas para testes de injeção.
- `javascript.txt`: Inventário de arquivos `.js`, `.mjs` e `.map`.
- `manual-review-only.txt`: Endpoints potencialmente destrutivos ou formulários POST preservados apenas para auditoria manual.
- `http.jsonl`: Logs estruturados de respostas HTTP com title, content-type e hash SHA-256 do corpo.
- `secret_indicators.jsonl`: Indicadores de credenciais encontradas em código frontend (sem expor valores sensíveis em texto puro).
- `url_provenance.jsonl`: Rastreamento da procedência de cada link (qual crawler ou ferramenta descobriu o endpoint).
- `js/*.js`: Bundles JavaScript arquivados localmente para análise estática offline.
- `tools/*.stdout` / `*.stderr`: Logs de execução de ferramentas externas.

---

## 🧪 Testes Automatizados

O motor possui suíte de testes unitários cobrindo normalização IDNA, regras de escopo, parser de HTML, extração de APIs/JSON, SQLite, controle de taxa e determinismo de resume:

```bash
python -m unittest discover -s tests -v
```

---

## 🗺️ Roadmap para a v3

1. **Captura de Tráfego Autenticado:** Mapeamento de sessões e extração de tokens JWT para crawling com privilégios.
2. **Matriz de Autorização Automatizada:** Testes diferenciais com duas contas de teste de níveis distintos para detecção de BOLA / IDOR.
3. **Favicon MurmurHash3:** Pivoting automático em motores como Shodan/Censys para descoberta de IPs de origem ocultos por CDN.
