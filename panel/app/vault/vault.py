#!/usr/bin/env python3
"""rds-vault — внешнее хранилище зашифрованных копий базы панели RDS.

Как нода Remnawave: панель выпускает хранилищу сертификат, подписанный своим CA, и упаковывает всё в VAULT_SECRET
(base64 JSON: vaultCertPem, vaultKeyPem, caCertPem). Хранилище слушает HTTPS с ОБЯЗАТЕЛЬНЫМ клиентским сертификатом
того же CA (взаимный TLS) — подключиться может только сервер RDS этой панели.

Только приём и список: удалить или перезаписать копию по сети нельзя (защита от шифровальщика на сервере RDS).
Старые копии хранилище чистит само: VAULT_KEEP_DAYS, VAULT_MAX_MB; самая свежая не удаляется никогда.
Копии приходят уже зашифрованными (age): хранилище их прочитать не может.

  PUT  /upload/<rds-ГГГГММДД-ЧЧММ.sql.gz.age>   тело — файл (до VAULT_MAX_FILE_MB)
  GET  /list                                    {"files":[{name,size,ts}], "free": байт, "total": байт}
  GET  /health                                  {"ok": true}
Только стандартная библиотека Python 3.
"""
import base64, json, os, re, shutil, ssl, tempfile, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

DATA = os.environ.get("VAULT_DATA", "/data")
PORT = int(os.environ.get("VAULT_PORT", "8743"))
KEEP_DAYS = int(os.environ.get("VAULT_KEEP_DAYS", "90"))
MAX_MB = int(os.environ.get("VAULT_MAX_MB", "51200"))
MAX_FILE = int(os.environ.get("VAULT_MAX_FILE_MB", "4096")) * 1048576
NAME_RX = re.compile(r"^rds-\d{8}(-\d{4})?\.sql\.gz(\.age)?$")
LOCK = threading.Lock()


def log(*a): print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def files():
    out = []
    for n in os.listdir(DATA):
        if NAME_RX.match(n):
            st = os.stat(os.path.join(DATA, n)); out.append({"name": n, "size": st.st_size, "ts": int(st.st_mtime)})
    return sorted(out, key=lambda f: -f["ts"])


def cleanup():
    fs = files()
    if not fs: return
    newest = fs[0]["name"]; now = time.time()
    for f in fs[1:]:
        if now - f["ts"] > KEEP_DAYS * 86400: os.remove(os.path.join(DATA, f["name"])); log("удалена по сроку", f["name"])
    fs = files(); total = sum(f["size"] for f in fs)
    for f in reversed(fs):
        if total <= MAX_MB * 1048576 or f["name"] == newest: break
        os.remove(os.path.join(DATA, f["name"])); total -= f["size"]; log("удалена по размеру", f["name"])


class H(BaseHTTPRequestHandler):
    server_version = "rds-vault"; sys_version = ""

    def send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def peer(self):
        try: return dict(x[0] for x in self.connection.getpeercert().get("subject", ())).get("commonName", "?")
        except Exception: return "?"

    def do_GET(self):
        if self.path == "/health": return self.send(200, {"ok": True})
        if self.path == "/list":
            fs = files(); du = shutil.disk_usage(DATA)
            return self.send(200, {"files": fs, "total": sum(f["size"] for f in fs), "free": du.free, "keep_days": KEEP_DAYS, "max_mb": MAX_MB})
        self.send(404, {"error": "not found"})

    def do_PUT(self):
        m = re.fullmatch(r"/upload/([^/]+)", self.path)
        if not m or not NAME_RX.match(m.group(1)): return self.send(400, {"error": "bad name"})
        name = m.group(1); dst = os.path.join(DATA, name)
        try: n = int(self.headers.get("Content-Length") or -1)
        except ValueError: n = -1
        if n <= 0 or n > MAX_FILE: return self.send(411 if n < 0 else 413, {"error": "bad length"})
        with LOCK:
            if os.path.exists(dst): return self.send(409, {"error": "exists", "name": name})   # перезаписать нельзя
            fd, tmp = tempfile.mkstemp(dir=DATA, prefix=".up-")
            try:
                left = n
                with os.fdopen(fd, "wb") as out:
                    while left > 0:
                        b = self.rfile.read(min(1 << 20, left))
                        if not b: raise IOError("обрыв передачи")
                        out.write(b); left -= len(b)
                os.chmod(tmp, 0o600); os.link(tmp, dst)   # link не перезапишет существующий файл
            except FileExistsError:
                return self.send(409, {"error": "exists", "name": name})
            except Exception as e:
                log("ошибка приёма", name, e); return self.send(500, {"error": str(e)})
            finally:
                if os.path.exists(tmp): os.remove(tmp)
            log("принята", name, n, "байт от", self.peer())
            cleanup()
        self.send(201, {"ok": True, "name": name, "size": n})

    do_POST = do_DELETE = do_PATCH = lambda self: self.send(405, {"error": "only upload and list"})

    def log_message(self, *a): pass


def main():
    sec = json.loads(base64.b64decode(os.environ["VAULT_SECRET"] + "=" * (-len(os.environ["VAULT_SECRET"]) % 4)))
    d = tempfile.mkdtemp(prefix="vault-tls-"); os.chmod(d, 0o700)
    for k, f in (("vaultCertPem", "cert.pem"), ("vaultKeyPem", "key.pem"), ("caCertPem", "ca.pem")):
        with open(os.path.join(d, f), "w") as fh: fh.write(sec[k])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "key.pem"))
    ctx.load_verify_locations(os.path.join(d, "ca.pem")); ctx.verify_mode = ssl.CERT_REQUIRED   # только клиенты с сертификатом панели
    shutil.rmtree(d)
    os.makedirs(DATA, exist_ok=True); cleanup()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log(f"rds-vault: порт {PORT}, данные {DATA}, хранить {KEEP_DAYS} дн., до {MAX_MB} МБ, копий: {len(files())}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
