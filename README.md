# VAULT — Banco Digital 🏦 (Laboratório de Segurança Web)

> **INFOESTE 2026 · Unoeste** — Mini-CTF de aplicações web.
> Aplicação **intencionalmente vulnerável** para treino de *ataque e defesa*.
> Mesmas 5 vulnerabilidades do Neon Shop, tema novo (banco digital).

> ⚠️ **AVISO:** este laboratório é inseguro de propósito. Rode **somente em `127.0.0.1`**.
> **Nunca** exponha na internet, não use em rede compartilhada e não coloque dados reais.

---

## 🎯 Os 5 desafios (900 pontos)

| # | Flag | Vulnerabilidade | Onde |
|---|------|-----------------|------|
| 1 | `VAULT{RECON_...}` | **Reconhecimento** (info exposta) | `/robots.txt` → `/api/internal/diag` |
| 2 | `VAULT{IDOR_...}`  | **Broken Access Control (IDOR)** | `/api/transactions/<id>` |
| 3 | `VAULT{SQLI_...}`  | **SQL Injection** | `/api/search?q=` |
| 4 | `VAULT{XSS_...}`   | **Cross-Site Scripting (armazenado)** | `/mensagens` |
| 5 | `VAULT{AUTH_...}`  | **Falha de autenticação (JWT)** | `/admin` → `/api/admin/reports` |

As flags são **geradas por máquina** (seed aleatória): cada PC tem flags diferentes — não dá para copiar do colega. Cole-as em **`/ctf`**.

---

## ✅ Pré-requisitos

- **Docker Desktop** instalado e **aberto** (engine Linux / WSL2 no Windows).
- **Git** (para clonar).
- Um navegador (Chrome ou Edge).

Verifique:
```bash
docker --version
docker compose version
docker info
```

---

## 🚀 Como rodar (Docker Compose)

### 1) Clonar o repositório
```bash
git clone https://github.com/SEU-USUARIO/vault-bank-infoeste.git
cd vault-bank-infoeste
```

### 2) Subir o laboratório (modo vulnerável)
```bash
docker compose up -d --build
```
Na primeira vez o build baixa a imagem base (`python:3.12-slim`) — pode demorar.

### 3) Conferir se está no ar
```bash
docker compose ps
curl.exe -i http://127.0.0.1:8099/api/health     # Windows (PowerShell)
curl     -i http://127.0.0.1:8099/api/health     # Linux/macOS
```
Esperado: `HTTP/1.0 200 OK` e `{"status":"ok","lab":"vault-bank","mode":"vulnerable"}`.

### 4) Abrir no navegador
```
http://127.0.0.1:8099/login
```

---

## 👤 Contas de teste

| E-mail | Papel | Senha |
|--------|-------|-------|
| `cliente@vault.local`  | cliente (Ana)     | `exemplo123` |
| `beatriz@vault.local`  | cliente (Beatriz) | `exemplo123` |
| `admin@vault.local`    | administrador     | `exemplo123` |

> Faça o CTF **logado como Ana** (`cliente@vault.local`): as evidências de IDOR e AUTH são liberadas para essa sessão.

---

## 🧭 Roteiro rápido (sem spoiler)

1. **RECON** — veja o que o `robots.txt` pede para "não indexar". Acesse esse caminho.
2. **IDOR** — seu extrato lista transações com um `id`. E se você pedir o `id` de **outra** transação na API?
3. **SQLi** — a busca de beneficiários monta a query concatenando sua entrada. Teste `/api/search?q=' OR '1'='1` no **Burp Repeater**.
4. **XSS** — o mural de mensagens renderiza o que você envia. Publique `<img src=x onerror="vaultProofXSS()">`.
5. **AUTH** — em `/admin`, leia o payload do seu JWT. Troque `role` para `admin` **mantendo a assinatura** e peça o relatório.

Detalhes passo a passo em [`docs/ALUNO.md`](docs/ALUNO.md).

---

## 🛡️ Modo seguro (ataque → defesa)

O **mesmo código** tem as correções, ativadas por variável de ambiente. Para ligar o modo seguro e ver os 5 ataques falharem:

```bash
docker compose -f compose.yaml -f compose.secure.yaml up -d --build --force-recreate
curl -i http://127.0.0.1:8099/api/health      # deve mostrar  "mode":"secure"
```
No modo seguro: IDOR → **404**, SQLi → registro oculto **some**, XSS → vira **texto**, JWT forjado → **401**, `/api/internal/diag` → **404**.

Voltar ao modo vulnerável:
```bash
docker compose up -d --build --force-recreate
```

---

## 🧪 Rodar os testes (opcional)

Valida os 5 ataques e as 5 defesas automaticamente (não precisa de Docker):
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## ⏹️ Parar / resetar

```bash
docker compose down            # para (preserva o volume e as flags)
docker compose down -v         # para e APAGA tudo (gera novas flags no próximo up)
```
> Durante a aula **não** use `down -v` — isso reseta o progresso e troca as flags.

---

## 🩺 Troubleshooting

| Sintoma | Causa provável | Solução |
|--------|----------------|---------|
| Porta não abre | Docker Desktop fechado | Abra o Docker e repita `docker compose up -d` |
| `port is already allocated` | 8099 em uso | Pare o processo na 8099 ou mude a porta no `compose.yaml` |
| Página carrega sem dados | container ainda subindo | Aguarde o healthcheck: `docker compose ps` |
| Flag "inválida" no `/ctf` | copiou sem `VAULT{` ou `}` | Copie a flag inteira |
| Quero ver logs | — | `docker compose logs -f vault` |

---

## 📁 Estrutura

```
vault-bank-infoeste/
├── app/
│   ├── server.py          # app (http.server + sqlite); vulnerável/seguro por env
│   └── web/               # SPA (index.html, app.js, style.css)
├── compose.yaml           # modo vulnerável (porta 127.0.0.1:8099)
├── compose.secure.yaml    # overlay do modo seguro
├── Dockerfile             # python:3.12-slim, non-root, read-only
├── docs/ALUNO.md          # guia do aluno
└── tests/test_lab.py      # testes E2E (ataque + defesa)
```

---

*Uso estritamente educacional — INFOESTE 2026.*
