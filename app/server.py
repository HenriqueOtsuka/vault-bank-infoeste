#!/usr/bin/env python3
"""
VAULT - Banco Digital :: Laboratorio INTENCIONALMENTE VULNERAVEL (INFOESTE 2026)
================================================================================
Mesmo motor do Neon Shop, tema reskin. 5 desafios: RECON, IDOR, SQLi, XSS, AUTH.
Alterne o modo pela variavel de ambiente VAULT_SECURITY_MODE = vulnerable | secure.

  NUNCA exponha este laboratorio na internet. Rode somente em 127.0.0.1.
"""
import os, re, json, sqlite3, hmac, hashlib, base64, secrets, html, time, mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MODE   = os.environ.get("VAULT_SECURITY_MODE", "vulnerable").strip().lower()
SECURE = MODE == "secure"
PORT   = int(os.environ.get("VAULT_PORT", "8099"))
BIND   = os.environ.get("VAULT_BIND", "127.0.0.1")
DB     = os.environ.get("VAULT_DB", os.path.join(os.path.dirname(__file__), "vault.db"))
WEB    = os.path.join(os.path.dirname(__file__), "web")
JWT_SECRET = b"dev-weak-secret-vault-2026"   # fraco de proposito (A04/A07)

# ---------------------------------------------------------------- flags / seed
def load_seed():
    p = os.path.join(os.path.dirname(DB), "vault_seed.txt")
    try:
        return open(p).read().strip()
    except Exception:
        s = secrets.token_hex(8)
        try: open(p, "w").write(s)
        except Exception: pass
        return s

SEED = load_seed()
def flag(key):
    h = hashlib.sha256(f"{SEED}::{key}".encode()).hexdigest()[:10].upper()
    return f"VAULT{{{key}_{h}}}"

FLAGS = {k: flag(k) for k in ["RECON", "IDOR", "SQLI", "XSS", "AUTH"]}
POINTS = {"RECON": 100, "IDOR": 150, "SQLI": 200, "XSS": 200, "AUTH": 250}

# ---------------------------------------------------------------- jwt (HS256)
def b64u(b):  return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64ud(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_make(payload):
    head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig  = b64u(hmac.new(JWT_SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"

def jwt_read(token, verify):
    try:
        head, body, sig = token.split(".")
    except Exception:
        return None
    if verify:  # modo seguro: confere algoritmo + assinatura
        try:
            if json.loads(b64ud(head)).get("alg") != "HS256":
                return None
        except Exception:
            return None
        expect = b64u(hmac.new(JWT_SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expect, sig):
            return None
    try:
        return json.loads(b64ud(body))
    except Exception:
        return None

# ---------------------------------------------------------------- db / seed
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def pwhash(p):
    return "pbkdf2$" + hashlib.pbkdf2_hmac("sha256", p.encode(), SEED.encode(), 50000).hex()

def seed_db():
    if os.path.exists(DB): os.remove(DB)
    c = db(); x = c.cursor()
    x.executescript("""
      CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, pw TEXT, role TEXT, name TEXT, account TEXT);
      CREATE TABLE transactions (id INTEGER PRIMARY KEY, owner_id TEXT, descricao TEXT, valor TEXT, evidence TEXT);
      CREATE TABLE beneficiaries (id INTEGER PRIMARY KEY, nome TEXT, banco TEXT, hidden INTEGER, segredo TEXT);
      CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, autor TEXT, texto TEXT);
      CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id TEXT);
      CREATE TABLE scores (session TEXT, challenge TEXT, PRIMARY KEY(session, challenge));
    """)
    users = [
        ("cliente-a", "cliente@vault.local", "client", "Ana (Cliente A)", "0001"),
        ("cliente-b", "beatriz@vault.local", "client", "Beatriz (Cliente B)", "0002"),
        ("admin",     "admin@vault.local",   "admin",  "Admin VAULT", "9000"),
    ]
    for uid, email, role, name, acc in users:
        x.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (uid, email, pwhash("exemplo123"), role, name, acc))
    # transacoes: 2001 = cliente-a ; 2002 = cliente-b (alvo do IDOR)
    x.execute("INSERT INTO transactions VALUES (?,?,?,?,?)", (2001, "cliente-a", "Pix recebido", "R$ 250,00", None))
    x.execute("INSERT INTO transactions VALUES (?,?,?,?,?)", (2002, "cliente-b", "Pix enviado - sigiloso", "R$ 14.900,00", FLAGS["IDOR"]))
    # beneficiarios: visiveis + 1 oculto (SQLi)
    for i, (nome, banco) in enumerate([("Padaria do Ze", "Bco 260"), ("Mercado Bom Preco", "Bco 341"),
                                        ("Farmacia Vida", "Bco 077"), ("Posto Central", "Bco 001")], start=1):
        x.execute("INSERT INTO beneficiaries VALUES (?,?,?,?,?)", (i, nome, banco, 0, None))
    x.execute("INSERT INTO beneficiaries VALUES (?,?,?,?,?)", (99, "[CONTA-LARANJA ARQUIVADA]", "Bco 000", 1, FLAGS["SQLI"]))
    c.commit(); c.close()

# ---------------------------------------------------------------- helpers http
class H(BaseHTTPRequestHandler):
    server_version = "VaultBankLab/1.0"
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *a):
        print("[VAULT]", self.address_string(), fmt % a)

    # ---- resposta
    def send_json(self, obj, code=200, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if SECURE:
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def send_html(self, path):
        full = os.path.join(WEB, path)
        if not os.path.isfile(full):
            self.send_json({"error": "not found"}, 404); return
        data = open(full, "rb").read()
        ctype = mimetypes.guess_type(full)[0] or "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if SECURE and ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers(); self.wfile.write(data)

    # ---- identidade
    def body_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def cookies(self):
        out = {}
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1); out[k] = v
        return out

    def current_user(self):
        sess = self.cookies().get("session")
        if not sess: return None
        c = db()
        if SECURE:  # token de sessao opaco mapeado no servidor
            row = c.execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?", (sess,)).fetchone()
        else:       # valor previsivel = id do usuario
            row = c.execute("SELECT * FROM users WHERE id=?", (sess,)).fetchone()
        c.close(); return row

    def session_id(self):
        return self.cookies().get("session")

    def mark(self, challenge):
        sid = self.session_id()
        if not sid: return
        c = db()
        try: c.execute("INSERT OR IGNORE INTO scores VALUES (?,?)", (sid, challenge)); c.commit()
        except Exception: pass
        c.close()

    # ================================================================= GET
    def do_GET(self):
        u = urlparse(self.path); path = u.path; q = parse_qs(u.query)

        if path == "/api/health":
            return self.send_json({"status": "ok", "lab": "vault-bank", "mode": MODE})

        if path == "/robots.txt":
            body = "User-agent: *\nDisallow: /api/internal/diag\nDisallow: /admin\n"
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body.encode()); return

        if path == "/api/internal/diag":
            if SECURE:  # endpoint interno escondido no modo seguro
                return self.send_json({"error": "not found"}, 404)
            return self.send_json({
                "service": "vault-internal-diag", "mode": MODE, "verify": "INSECURE",
                "build": "2026.1", "db": os.path.basename(DB), "evidence": FLAGS["RECON"],
                "hint": "reconhecimento: endpoints internos nao deveriam estar acessiveis",
            })

        if path == "/api/me":
            row = self.current_user()
            if not row: return self.send_json({"error": "unauthorized"}, 401)
            tok = jwt_make({"sub": row["id"], "role": row["role"], "name": row["name"], "iat": int(time.time())})
            return self.send_json({"user": {"id": row["id"], "role": row["role"], "name": row["name"],
                                            "account": row["account"]}, "token": tok})

        m = re.match(r"^/api/transactions/(\d+)$", path)
        if m:
            tid = int(m.group(1)); me = self.current_user()
            if not me: return self.send_json({"error": "unauthorized"}, 401)
            c = db()
            if SECURE:  # IDOR corrigido: restringe ao dono autenticado
                row = c.execute("SELECT * FROM transactions WHERE id=? AND owner_id=?", (tid, me["id"])).fetchone()
            else:       # VULNERAVEL: busca so pelo id, ignora o dono
                row = c.execute("SELECT * FROM transactions WHERE id=?", (tid,)).fetchone()
            c.close()
            if not row: return self.send_json({"error": "not found"}, 404)
            out = {"id": row["id"], "owner_id": row["owner_id"], "descricao": row["descricao"], "valor": row["valor"]}
            if row["evidence"] and me["id"] == "cliente-a":
                out["evidence"] = row["evidence"]; self.mark("IDOR")
            return self.send_json({"transaction": out})

        if path == "/api/transactions":
            me = self.current_user()
            if not me: return self.send_json({"error": "unauthorized"}, 401)
            c = db(); rows = c.execute("SELECT id,descricao,valor FROM transactions WHERE owner_id=?", (me["id"],)).fetchall(); c.close()
            return self.send_json({"transactions": [dict(r) for r in rows]})

        if path == "/api/search":
            term = (q.get("q", ["%"])[0]) or "%"
            c = db()
            if SECURE:  # parametrizado: a entrada vira dado literal, nunca codigo
                rows = c.execute("SELECT id,nome,banco,hidden,segredo FROM beneficiaries WHERE nome LIKE ? AND hidden=0", (term,)).fetchall()
            else:       # VULNERAVEL: concatena a entrada direto na query (term = padrao inteiro do LIKE)
                sql = "SELECT id,nome,banco,hidden,segredo FROM beneficiaries WHERE hidden=0 AND nome LIKE '" + term + "' LIMIT 30"
                try: rows = c.execute(sql).fetchall()
                except Exception as e:
                    c.close(); return self.send_json({"error": "sql", "detail": str(e)}, 400)
            c.close()
            out = []
            for r in rows:
                item = {"id": r["id"], "nome": r["nome"], "banco": r["banco"], "hidden": r["hidden"]}
                if r["segredo"]:
                    item["descricao"] = "Evidencia: " + r["segredo"]; self.mark("SQLI")
                out.append(item)
            return self.send_json({"count": len(out), "beneficiaries": out})

        if path == "/api/notes":
            c = db(); rows = c.execute("SELECT autor,texto FROM notes ORDER BY id DESC LIMIT 50").fetchall(); c.close()
            return self.send_json({"notes": [dict(r) for r in rows]})

        if path == "/api/admin/reports":
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else None
            claims = jwt_read(tok, verify=SECURE) if tok else None
            if not claims:
                return self.send_json({"error": "unauthorized"}, 401)
            if SECURE:  # confere a role REAL no banco, nao a claim do token
                c = db(); row = c.execute("SELECT role FROM users WHERE id=?", (claims.get("sub"),)).fetchone(); c.close()
                if not row or row["role"] != "admin":
                    return self.send_json({"error": "forbidden"}, 403)
            else:       # VULNERAVEL: confia na claim role sem verificar assinatura
                if claims.get("role") != "admin":
                    return self.send_json({"error": "forbidden"}, 403)
            out = {"receita_total": "R$ 1.284.000,00", "contas": 300123, "alertas_fraude": 7}
            if claims.get("sub") == "cliente-a":
                out["evidence"] = FLAGS["AUTH"]; self.mark("AUTH")
            return self.send_json({"report": out})

        if path == "/api/ctf/scoreboard":
            sid = self.session_id(); c = db()
            got = [r["challenge"] for r in c.execute("SELECT challenge FROM scores WHERE session=?", (sid,)).fetchall()] if sid else []
            c.close()
            total = sum(POINTS[g] for g in got)
            return self.send_json({"solved": got, "score": total, "max": sum(POINTS.values()),
                                   "challenges": list(POINTS.keys())})

        # paginas / estaticos
        if path in ("/", "/login", "/extrato", "/search", "/mensagens", "/admin", "/ctf"):
            return self.send_html("index.html")
        if path.startswith("/static/"):
            return self.send_html(path.replace("/static/", "", 1))

        return self.send_json({"error": "not found"}, 404)

    # ================================================================= POST
    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/login":
            d = self.body_json()
            c = db(); row = c.execute("SELECT * FROM users WHERE email=?", (d.get("email", ""),)).fetchone()
            if not row or row["pw"] != pwhash(d.get("password", "")):
                c.close(); return self.send_json({"error": "credenciais invalidas"}, 401)
            if SECURE:  # cookie opaco + mapeamento no servidor
                sess = secrets.token_hex(16)
                c.execute("INSERT INTO sessions VALUES (?,?)", (sess, row["id"])); c.commit()
            else:       # VULNERAVEL: cookie = id previsivel
                sess = row["id"]
            c.close()
            tok = jwt_make({"sub": row["id"], "role": row["role"], "name": row["name"], "iat": int(time.time())})
            cookie = f"session={sess}; Path=/; HttpOnly; SameSite=Lax"
            return self.send_json({"user": {"id": row["id"], "role": row["role"], "name": row["name"],
                                            "account": row["account"]}, "token": tok},
                                  extra=[("Set-Cookie", cookie)])

        if path == "/api/notes":
            me = self.current_user()
            if not me: return self.send_json({"error": "unauthorized"}, 401)
            d = self.body_json(); texto = str(d.get("texto", ""))[:500]
            # armazenamento cru nos dois modos; a diferenca de XSS esta na renderizacao (front)
            c = db(); c.execute("INSERT INTO notes (autor, texto) VALUES (?,?)", (me["name"], texto)); c.commit(); c.close()
            return self.send_json({"ok": True})

        if path == "/api/ctf/xss-proof":
            if SECURE:  # no modo seguro o payload nao executa, entao o endpoint fica bloqueado
                return self.send_json({"error": "forbidden"}, 403)
            self.mark("XSS")
            return self.send_json({"ok": True, "evidence": FLAGS["XSS"]})

        if path == "/api/ctf/submit":
            d = self.body_json(); val = str(d.get("flag", "")).strip()
            for k, f in FLAGS.items():
                if val == f:
                    self.mark(k)
                    return self.send_json({"correct": True, "challenge": k, "points": POINTS[k]})
            return self.send_json({"correct": False})

        return self.send_json({"error": "not found"}, 404)


def main():
    seed_db()
    banner = "INTENCIONALMENTE VULNERAVEL" if not SECURE else "modo seguro (mitigado)"
    print(f"[VAULT] {banner} - mode={MODE}")
    print(f"[VAULT] http://{BIND}:{PORT}  (NAO EXPONHA NA INTERNET)")
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()


if __name__ == "__main__":
    main()
