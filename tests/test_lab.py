from urllib.parse import quote
import os, re, json, base64, subprocess, sys, time, urllib.request, urllib.error, unittest, tempfile, signal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_server(mode, port, dbdir):
    env = dict(os.environ, VAULT_SECURITY_MODE=mode, VAULT_PORT=str(port),
               VAULT_BIND="127.0.0.1", VAULT_DB=os.path.join(dbdir, "vault.db"))
    p = subprocess.Popen([sys.executable, "-m", "app.server"], cwd=ROOT, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try: urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1); return p
        except Exception: time.sleep(0.1)
    p.kill(); raise RuntimeError("server nao subiu")

def req(port, path, method="GET", body=None, headers=None, cookie=None):
    url = f"http://127.0.0.1:{port}{path}"
    h = {"Content-Type": "application/json"}; h.update(headers or {})
    if cookie: h["Cookie"] = cookie
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=3)
        return resp.status, json.loads(resp.read() or b"{}"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}"), e.headers

def login(port, email="cliente@vault.local"):
    s, j, hdr = req(port, "/api/login", "POST", {"email": email, "password": "exemplo123"})
    cookie = hdr.get("Set-Cookie", "").split(";")[0]
    return cookie, j.get("token")

def forge_admin(token):
    h, p, sig = token.split(".")
    obj = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))); obj["role"] = "admin"
    np = base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{h}.{np}.{sig}"

class Vulnerable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(); cls.p = run_server("vulnerable", 8191, cls.dir); cls.port = 8191
    @classmethod
    def tearDownClass(cls): cls.p.kill()

    def test_health(self):
        s, j, _ = req(self.port, "/api/health"); self.assertEqual(j["mode"], "vulnerable")
    def test_recon(self):
        s, j, _ = req(self.port, "/api/internal/diag"); self.assertEqual(s, 200); self.assertIn("RECON", j["evidence"])
    def test_idor(self):
        ck, _ = login(self.port)
        s, j, _ = req(self.port, "/api/transactions/2002", cookie=ck)
        self.assertEqual(s, 200); self.assertEqual(j["transaction"]["owner_id"], "cliente-b")
        self.assertIn("IDOR", j["transaction"]["evidence"])
    def test_sqli(self):
        ck, _ = login(self.port)
        s, j, _ = req(self.port, "/api/search?q=" + quote("' OR '1'='1") + "", cookie=ck)
        hid = [b for b in j["beneficiaries"] if b["id"] == 99]
        self.assertTrue(hid and "SQLI" in hid[0]["descricao"])
    def test_xss_proof(self):
        ck, _ = login(self.port)
        s, j, _ = req(self.port, "/api/ctf/xss-proof", "POST", cookie=ck)
        self.assertEqual(s, 200); self.assertIn("XSS", j["evidence"])
    def test_auth_forge(self):
        ck, tok = login(self.port)
        s, j, _ = req(self.port, "/api/admin/reports", headers={"Authorization": "Bearer " + forge_admin(tok)})
        self.assertEqual(s, 200); self.assertIn("AUTH", j["report"]["evidence"])

class Secure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(); cls.p = run_server("secure", 8192, cls.dir); cls.port = 8192
    @classmethod
    def tearDownClass(cls): cls.p.kill()

    def test_health(self):
        s, j, _ = req(self.port, "/api/health"); self.assertEqual(j["mode"], "secure")
    def test_recon_blocked(self):
        s, _, _ = req(self.port, "/api/internal/diag"); self.assertEqual(s, 404)
    def test_idor_blocked(self):
        ck, _ = login(self.port)
        s, _, _ = req(self.port, "/api/transactions/2002", cookie=ck); self.assertEqual(s, 404)
        s2, _, _ = req(self.port, "/api/transactions/2001", cookie=ck); self.assertEqual(s2, 200)
    def test_sqli_blocked(self):
        ck, _ = login(self.port)
        s, j, _ = req(self.port, "/api/search?q=" + quote("' OR '1'='1") + "", cookie=ck)
        self.assertEqual(len([b for b in j["beneficiaries"] if b["id"] == 99]), 0)
    def test_xss_proof_blocked(self):
        ck, _ = login(self.port)
        s, _, _ = req(self.port, "/api/ctf/xss-proof", "POST", cookie=ck); self.assertEqual(s, 403)
    def test_auth_forge_blocked(self):
        ck, tok = login(self.port)
        s, _, _ = req(self.port, "/api/admin/reports", headers={"Authorization": "Bearer " + forge_admin(tok)})
        self.assertEqual(s, 401)

if __name__ == "__main__":
    unittest.main(verbosity=2)
