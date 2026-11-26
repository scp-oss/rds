"""RDS panel: админка RustDesk + страница установки + API для клиентов.

ADMIN_HOST  (rds.example.com)  — вход по логину, список устройств, пароли, сборки.
CLIENT_HOST (rd.example.com)  — скачать exe/dmg/deb, скрипты установки.
/api/*      (оба хоста)         — heartbeat/sysinfo от клиентов RustDesk и регистрация из установщиков.
Данные: PostgreSQL (PG_DSN) и Redis (REDIS_URL); файлы — /data/panel (cache — только последняя версия клиента, dist — собранные установщики).
"""
import base64, hashlib, hmac, json, os, re, shutil, sqlite3, subprocess, tempfile, threading, time, urllib.request, urllib.parse
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse, RedirectResponse, Response

E = os.environ.get
ADMIN_HOST = E("ADMIN_HOST", "rds.example.com")
CLIENT_HOST = E("CLIENT_HOST", "rd.example.com")
RDS_HOST = E("RDS_HOST", "rds.example.com")          # ID/relay сервер для клиентов (стандартные порты)
API_URL = E("API_URL") or f"https://{ADMIN_HOST}"    # api-server в клиентах (другой адрес — если админка не на 443, напр. через CLIENT_HOST)
CLIENT_URL = E("CLIENT_URL", f"https://{CLIENT_HOST}")
ADMIN_USER = E("ADMIN_USER", "admin")
ADMIN_PASSWORD = E("ADMIN_PASSWORD", "")
def _secret():
    """Ключ подписи сессий: SECRET_KEY из окружения, иначе случайный, сохранённый в PANEL_DIR/.secret_key (600)."""
    s = E("SECRET_KEY")
    if s: return s.encode()
    f = Path(E("PANEL_DIR", "/data/panel")) / ".secret_key"
    try:
        k = f.read_bytes().strip()
        if len(k) >= 32: return k
    except OSError: pass
    f.parent.mkdir(parents=True, exist_ok=True)
    k = base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=")
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, k); os.close(fd)
    return k
SECRET = _secret()
REG_TOKEN = E("REG_TOKEN", "")
PROXY_URL = E("PROXY_URL", "")
KEY_FILE = Path(E("KEY_FILE", "/data/id_ed25519.pub"))
HBBS_DB = Path(E("HBBS_DB", "/data/db_v2.sqlite3"))
D = Path(E("PANEL_DIR", "/data/panel"))
CACHE, DIST = D / "cache", D / "dist"
TPL = Path(__file__).parent / "templates"
ONLINE_SEC = 40   # RustDesk шлёт отметку каждые 15 с — «не в сети» после двух пропущенных с запасом
# Клиент 1.5.x, вошедший в аккаунт, требует от hbbs обмен ключами по TCP, которого нет в открытом hbbs →
# «Failed to secure tcp». Адрес «ID@сервер?key=…» идёт мимо этой проверки. Выключить (CLIENT_SPECIAL_IDS=0),
# когда hbbs научится обмену ключами.
SPECIAL_IDS = E("CLIENT_SPECIAL_IDS", "1") == "1"
CHECK_EVERY = 6 * 3600

D.mkdir(parents=True, exist_ok=True); os.chmod(D, 0o700)
CACHE.mkdir(exist_ok=True); DIST.mkdir(exist_ok=True)

# ---------------------------------------------------------------- база данных
# PostgreSQL (PG_DSN) — единственная база панели (с 2026-11-17; SQLite убран). Своя SQLite у hbbs (HBBS_DB) — только чтение.
# Запросы в коде написаны в диалекте SQLite («?», «insert or ignore»); для PostgreSQL их переводит _pg().
import functools
PG_DSN = E("PG_DSN", "")

class Row(tuple):
    """Строка результата: r[0] и r["колонка"], dict(r) — как sqlite3.Row."""
    def __new__(cls, values, idx):
        r = tuple.__new__(cls, values); r._i = idx; return r
    def __getitem__(self, k): return tuple.__getitem__(self, self._i[k] if isinstance(k, str) else k)
    def keys(self): return list(self._i)

if not PG_DSN: raise SystemExit("PG_DSN не задан: панели нужна база PostgreSQL (см. docker-compose.yml, rds-postgres)")
import psycopg
from psycopg_pool import ConnectionPool

def _row_factory(cur):
    idx = {d.name: n for n, d in enumerate(cur.description or [])}
    return lambda values: Row(values, idx)

POOL = ConnectionPool(PG_DSN, min_size=1, max_size=12, timeout=20, kwargs={"row_factory": _row_factory}, open=True)
_INS_IGNORE = re.compile(r"\binsert\s+or\s+ignore\s+into\b", re.I)

@functools.lru_cache(maxsize=1024)
def _pg(q):
    ign = bool(_INS_IGNORE.search(q)); q = _INS_IGNORE.sub("insert into", q)
    q = q.replace("%", "%%").replace("?", "%s")
    return q + (" on conflict do nothing" if ign else "")

class _PgConn:
    """with db() as c: c.execute(...) — одна транзакция, commit при выходе, rollback при ошибке."""
    def __init__(self): self._cm = POOL.connection()
    def __enter__(self): self.c = self._cm.__enter__(); return self
    def __exit__(self, *a): return self._cm.__exit__(*a)
    def execute(self, q, p=()): return self.c.execute(_pg(q), tuple(p))

def db(): return _PgConn()

with db() as c:
    c.execute("""create table if not exists devices(
        id text primary key, uuid text, hostname text, username text, os text, version text,
        cpu text, memory text, master int, password text, note text default '',
        installed_at bigint, sysinfo_at bigint, last_seen bigint, last_ip text, source text,
        group_name text default '', owner text default '', local_ip text default '', ext_ip text default '', mac text default '', want_master int)""")
    c.execute("alter table devices add column if not exists want_master int")
    for col in ("disk", "nic", "hw_at", "hw_cpu", "hw_ram", "gpu", "printers", "pc_users", "logged_user", "scanners", "activation", "office", "office_detail", "board", "gpu_mem", "cpu_cores", "cpu_threads", "ram_type", "bt", "antivirus", "software", "sw_at", "cmd", "cmd_at", "cmd_result", "agent_at"): c.execute(f"alter table devices add column if not exists {col} text default ''")
    c.execute("create table if not exists hw_history(id text, ts bigint, field text, old text, new text)")
    c.execute("create index if not exists hw_history_id on hw_history(id, ts)")
    c.execute("""create table if not exists users(
        username text primary key, display_name text default '', pw_hash text, is_admin int default 0,
        group_name text default '', note text default '', created_at bigint, last_login bigint, source text default 'local')""")
    # второй фактор (TOTP) и версия сессий: смена версии мгновенно завершает все сессии пользователя
    c.execute("alter table users add column if not exists totp_secret text default ''")
    c.execute("alter table users add column if not exists totp_on int default 0")
    c.execute("alter table users add column if not exists totp_last bigint default 0")
    c.execute("alter table users add column if not exists sess_ver int default 0")
    c.execute("alter table users add column if not exists elev_until bigint default 0")
    c.execute("alter table users add column if not exists totp_drift int default 0")
    # шаблоны прав (роли): пользователю, группе панели и группе AD; права = объединение всех его ролей
    c.execute("create table if not exists roles(name text primary key, title text, perms text default '[]', builtin int default 0, created_at bigint)")
    c.execute("alter table users add column if not exists role text default ''")
    c.execute("alter table users add column if not exists ad_roles text default '[]'")       # роли из сопоставления групп AD (пересчёт при входе)
    c.execute("alter table users add column if not exists ad_manual int default 0")          # доменный пользователь, одобренный вручную
    c.execute("alter table users add column if not exists manual_groups text default '[]'")  # его группы, заданные администратором
    c.execute("create table if not exists ad_maps(id bigserial primary key, ad_group text, panel_groups text default '[]', role text default '', created_at bigint)")
    c.execute("create table if not exists ad_pending(username text primary key, display_name text, ad_groups text default '[]', ip text, ts bigint, attempts int default 1)")       # смещение часов телефона, шагов по 30 с
    c.execute("alter table users add column if not exists totp_resync text default ''")    # «смещение:шаг» первого кода пары при большом расхождении
    c.execute("create table if not exists admin_log(id bigserial primary key, ts bigint, username text, ip text, action text, target text, ok int default 1)")
    c.execute("create table if not exists tokens(token_sha text primary key, username text, created_at bigint, last_used bigint, client_id text, client_uuid text)")
    c.execute("create table if not exists ab(username text primary key, data text, updated_at bigint, auto text default '[]')")
    c.execute("create table if not exists favs(username text, id text, primary key(username, id))")
    c.execute("create table if not exists groups(name text primary key, note text default '', created_at bigint)")
    c.execute("alter table groups add column if not exists role text default ''")
    c.execute("create table if not exists user_groups(username text, group_name text, primary key(username, group_name))")
    c.execute("create table if not exists audit(ts bigint, kind text, id text, peer_id text, peer_name text, ip text, action text, raw text)")
    c.execute("create table if not exists settings(k text primary key, v text)")
    # права обычных пользователей панели (админу всё разрешено); правило можно дать пользователю или группе
    for t in ("users", "groups"):
        for col in ("can_connect", "can_password"): c.execute(f"alter table {t} add column if not exists {col} int default 0")
    c.execute("alter table devices add column if not exists inst_user text default ''")   # кто запустил установщик RustDesk
    # ключ агента (2026-11-24): у каждого ПК свой; в базе только sha256, общий REG_TOKEN — лишь до привязки
    for col in ("agent_key_sha", "agent_key_at", "agent_bind_until"): c.execute(f"alter table devices add column if not exists {col} text default ''")
    # компьютер может быть в нескольких группах; devices.group_name остаётся «первой группой» (для RustDesk API)
    c.execute("create table if not exists device_groups(id text, group_name text, primary key(id, group_name))")
    c.execute("insert into device_groups(id, group_name) select id, group_name from devices where coalesce(group_name,'')<>'' on conflict do nothing")
    # имя и фамилия пользователя ПК: person — вписано вручную (ПК не в домене), person_ad — displayName из AD/FreeIPA
    for col in ("person", "person_ad"): c.execute(f"alter table devices add column if not exists {col} text default ''")
    # каталог программ и задания установки/удаления (агент забирает раз в минуту через /api/rds/poll)
    c.execute("""create table if not exists sw_packages(id bigserial primary key, name text, platform text, kind text,
        source text default '', file text default '', file_name text default '', file_size bigint default 0, sha256 text default '',
        install_args text default '', uninstall_kind text default '', uninstall_args text default '', detect_name text default '',
        config text default '', note text default '', created_at bigint, updated_at bigint)""")
    c.execute("""create table if not exists sw_jobs(id bigserial primary key, device_id text, package_id bigint, pkg_name text,
        action text, status text, msg text default '', secret text, spec text, created_by text,
        created_at bigint, started_at bigint, finished_at bigint)""")
    c.execute("create index if not exists sw_jobs_dev on sw_jobs(device_id, status)")
    c.execute("alter table sw_packages add column if not exists post_script text default ''")
    c.execute("create index if not exists audit_ts on audit(ts)")
    c.execute("create index if not exists tokens_user on tokens(username)")

# ---------------------------------------------------------------- пользователи (панель + аккаунт RustDesk)
def pw_hash(pw, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()

def pw_check(pw, stored):
    try:
        _, salt, h = (stored or "").split("$")
        return hmac.compare_digest(pw_hash(pw, base64.b64decode(salt)), stored)
    except ValueError:
        return False

USER_RX = re.compile(r"^[A-Za-z0-9._@-]{2,40}$")
with db() as c:   # первый админ — из .env (ADMIN_USER / ADMIN_PASSWORD)
    if ADMIN_PASSWORD and not c.execute("select 1 from users").fetchone():
        c.execute("insert into users(username, display_name, pw_hash, is_admin, created_at) values(?,?,?,1,?)",
                  (ADMIN_USER, "Администратор", pw_hash(ADMIN_PASSWORD), int(time.time())))

def get_user(name):
    with db() as c: return c.execute("select * from users where username=?", (name,)).fetchone()

def check_login(name, pw):
    """Локальный пользователь → его пароль; иначе (или если это пользователь из AD) → Active Directory."""
    name = str(name or "").strip(); pw = str(pw or "")
    u = get_user(name)
    if u and (u["source"] or "local") != "ad":
        if pw_check(pw, u["pw_hash"]): return u
        return None                    # локальная учётка с таким логином — в AD не идём (нельзя «перехватить» логин)
    if ad_cfg().get("enabled") == "1" and pw:
        try:
            r = ad_login(name, pw)
            if r == "PENDING": return "PENDING"
            if r: return r
        except Exception as e:
            print("[ad] ошибка:", type(e).__name__, str(e)[:200], flush=True)
    pw_check("x", "scrypt$AAAAAAAAAAAAAAAAAAAAAA==$AAAA")   # выравниваем время ответа
    return None

# ---------------------------------------------------------------- Active Directory (LDAP)
# kind: "ad" — Windows Active Directory, "freeipa" — FreeIPA (389 DS: uid, memberOf, nsAccountLock)
AD_KEYS = ("enabled", "kind", "url", "base_dn", "bind_user", "bind_pw", "admin_group", "group_prefix", "upn_suffix")
AD_DEFAULTS = {"enabled": "0", "kind": "ad", "url": "", "base_dn": "", "bind_user": "", "bind_pw": "", "admin_group": "RDS Admins", "group_prefix": "RDS ", "upn_suffix": ""}
KIND_NAME = {"ad": "AD", "freeipa": "FreeIPA"}

def bind_dn(cfg, user=None):
    """Логин сервисной учётки → то, чем делать bind. AD понимает user@домен и ДОМЕН\\user; FreeIPA — только DN."""
    u = (cfg["bind_user"] if user is None else user).strip()
    if cfg.get("kind") == "freeipa" and u and "=" not in u:
        u = f"uid={u.split('@')[0]},cn=users,cn=accounts,{cfg['base_dn']}"
    return u

def ad_cfg():
    with db() as c: v = {r[0][3:]: r[1] for r in c.execute("select k, v from settings where k like 'ad_%'")}
    return {k: v.get(k, AD_DEFAULTS[k]) for k in AD_KEYS}

def _ad_server(cfg):
    from ldap3 import Server, Tls
    import ssl
    url = cfg["url"].strip()
    tls = Tls(validate=ssl.CERT_NONE) if url.lower().startswith("ldaps://") else None
    return Server(url, connect_timeout=5, tls=tls, get_info=None)

def _ad_service(cfg):
    from ldap3 import Connection
    u = bind_dn(cfg)
    c = (Connection(_ad_server(cfg), user=u, password=cfg["bind_pw"], receive_timeout=8, raise_exceptions=False) if u
         else Connection(_ad_server(cfg), receive_timeout=8, raise_exceptions=False))      # пусто — анонимно (FreeIPA разрешает поиск)
    if not c.bind():
        msg = str(c.result.get("message", ""))
        codes = {"52e": "неверный логин или пароль", "525": "такой учётки нет", "530": "вход в это время запрещён", "531": "вход с этого компьютера запрещён",
                 "532": "срок пароля истёк", "533": "учётка отключена", "701": "срок учётки истёк", "773": "нужно сменить пароль", "775": "учётка заблокирована"}
        code = next((v for k, v in codes.items() if f"data {k}" in msg), None)
        raise RuntimeError("учётка " + (u or "(анонимно)") + " не вошла: " + (code or (str(c.result.get("description")) + " " + msg[:120])))
    return c

def ad_lookup(cfg, login):
    """Найти пользователя (AD: sAMAccountName; FreeIPA: uid; можно user@домен и ДОМЕН\\user)
    → (dn, логин, отображаемое имя, [группы с учётом вложенности], отключён?)."""
    from ldap3.utils.conv import escape_filter_chars as esc
    sam = login.split("\\")[-1].split("@")[0].strip()
    if not sam: return None
    svc = _ad_service(cfg)
    try:
        if cfg.get("kind") == "freeipa":
            # только cn=users,cn=accounts: в cn=compat FreeIPA дублирует тех же пользователей
            svc.search(f"cn=users,cn=accounts,{cfg['base_dn']}", f"(&(objectClass=posixAccount)(uid={esc(sam)}))",
                       attributes=["uid", "displayName", "cn", "memberOf", "nsAccountLock"], size_limit=2)
            if len(svc.entries) != 1: return None
            e = svc.entries[0]; dn = e.entry_dn
            disabled = str(e.nsAccountLock.value if "nsAccountLock" in e else "").upper() == "TRUE"
            groups = sorted({g.split(",")[0].split("=", 1)[1] for g in (e.memberOf.values if "memberOf" in e else [])
                             if ",cn=groups,cn=accounts," in g.lower()})
            name = str(e.uid.value); disp = str(e.displayName.value if "displayName" in e and e.displayName.value else (e.cn.value if "cn" in e else ""))
            return dn, name, disp, groups, disabled
        svc.search(cfg["base_dn"], f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={esc(sam)}))",
                   attributes=["distinguishedName", "displayName", "sAMAccountName", "userAccountControl"], size_limit=2)
        if len(svc.entries) != 1: return None
        e = svc.entries[0]; dn = str(e.distinguishedName)
        disabled = bool(int(str(e.userAccountControl or 0) or 0) & 2)
        svc.search(cfg["base_dn"], f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={esc(dn)}))", attributes=["cn"], size_limit=500)
        groups = sorted(str(g.cn) for g in svc.entries)
        return dn, str(e.sAMAccountName), str(e.displayName or "") if e.displayName else "", groups, disabled
    finally:
        svc.unbind()

def ad_map(cfg, groups):
    """Группы AD → (админ?, группы панели). «RDS Office» при префиксе «RDS » → «Office»."""
    adm = cfg["admin_group"].strip().lower(); pre = cfg["group_prefix"]
    is_admin = bool(adm) and any(g.lower() == adm for g in groups)
    mapped = [g[len(pre):].strip() for g in groups if pre and g.lower().startswith(pre.lower()) and g.lower() != adm]
    return is_admin, [g for g in mapped if g and GROUP_RX.match(g)]

def ad_login(login, pw):
    from ldap3 import Connection
    cfg = ad_cfg()
    found = ad_lookup(cfg, login)
    if not found: return None
    dn, sam, disp, groups, disabled = found
    if disabled: return None
    uc = Connection(_ad_server(cfg), user=dn, password=pw, receive_timeout=8, raise_exceptions=False)
    ok = uc.bind(); uc.unbind()
    if not ok: return None
    is_admin, mapped = ad_map(cfg, groups)
    # сопоставления «группа AD → группы ПК + шаблон» (таблица в админке), без учёта регистра
    lg = {g.lower() for g in groups}; ad_roles = []
    with db() as c:
        for m in c.execute("select * from ad_maps"):
            if (m["ad_group"] or "").lower() in lg:
                mapped += [g for g in _jl(m["panel_groups"]) if GROUP_RX.match(g)]
                if m["role"] == "admin": is_admin = True
                elif m["role"]: ad_roles.append(m["role"])
    mapped = sorted(set(mapped), key=str.lower); ad_roles = sorted(set(ad_roles))
    name = sam.lower()
    if not USER_RX.match(name): return None
    with db() as c:
        ex = c.execute("select * from users where username=?", (name,)).fetchone()
        if ex and (ex["source"] or "local") != "ad": return None
        manual = bool(ex and ex["ad_manual"])
        if not is_admin and not mapped and not ad_roles and not manual:
            if setting("ad_approval", "0") == "1":
                c.execute("insert into ad_pending(username, display_name, ad_groups, ip, ts) values(?,?,?,?,?) on conflict(username) do update set "
                          "display_name=excluded.display_name, ad_groups=excluded.ad_groups, ts=excluded.ts, attempts=ad_pending.attempts+1",
                          (name, disp or sam, json.dumps(groups, ensure_ascii=False), "", now()))
                print(f"[ad] {sam}: пароль верный, групп RDS нет — ждёт одобрения администратора", flush=True); return "PENDING"
            print(f"[ad] {sam}: пароль верный, но нет групп RDS — вход запрещён", flush=True); return None
        adm = int(is_admin or bool(ex and ex["role"] == "admin"))
        if ex and manual: adm = int(is_admin or bool(ex["is_admin"]))
        if ex: c.execute("update users set display_name=?, is_admin=?, ad_roles=? where username=?", (disp or sam, adm, json.dumps(ad_roles), name))
        else: c.execute("insert into users(username, display_name, pw_hash, is_admin, group_name, note, created_at, source, ad_roles) values(?,?,?,?,'',?,?, 'ad', ?)",
                        (name, disp or sam, "", adm, "из Active Directory", now(), json.dumps(ad_roles)))
        if manual: mapped = sorted(set(mapped) | set(_jl(ex["manual_groups"])), key=str.lower)
        set_user_groups(c, name, mapped)   # группы AD-пользователя: из AD (+ заданные администратором при одобрении)
    print(f"[ad] вход {name}: админ={is_admin} группы={mapped}", flush=True)
    return get_user(name)

def now(): return int(time.time())

def upsert(id_, **f):
    with db() as c:
        if not c.execute("select 1 from devices where id=?", (id_,)).fetchone():
            c.execute("insert into devices(id) values(?)", (id_,))
        if f:
            c.execute(f"update devices set {', '.join(k + '=?' for k in f)} where id=?", (*f.values(), id_))

# ---------------------------------------------------------------- config string
def server_key(): return KEY_FILE.read_text().strip() if KEY_FILE.exists() else ""

def config_string():
    j = json.dumps({"host": RDS_HOST, "relay": RDS_HOST, "key": server_key(), "api": API_URL}, separators=(",", ":"))
    return base64.urlsafe_b64encode(j.encode()).decode().rstrip("=")[::-1]

def _collector_ver(*names):
    """Версия сборщика = хеш исходников; агенты сравнивают её с вшитой в свой скрипт и при расхождении обновляются."""
    h = hashlib.sha1()
    for n in names: h.update((TPL / n).read_bytes())
    return h.hexdigest()[:12]
HWV_WIN = _collector_ver("hw.ps1", "hw-core.ps1")
HWV_UNIX = _collector_ver("hw.sh")

def render(name, master, base=None, login_token="", login_user=""):
    s = (TPL / name).read_text(encoding="utf-8")
    for k, v in {"__LOGIN_TOKEN__": login_token, "__LOGIN_USER__": login_user, "__CFG__": config_string(), "__API__": API_URL, "__RDS__": RDS_HOST, "__TOKEN__": REG_TOKEN, "__BASE__": base or CLIENT_URL,
                 "__MASTER__": ("$true" if master else "$false") if name.endswith(".ps1") else ("1" if master else "0"),
                 "__Q__": "" if master else "?master=0",
                 "__HWV__": HWV_WIN if name.endswith(".ps1") else HWV_UNIX,
                 "__HWPS__": (TPL / "hw-core.ps1").read_text(encoding="utf-8") if "__HWPS__" in s else ""}.items():
        s = s.replace(k, v)
    return s

# ---------------------------------------------------------------- builder
STATE = {"version": None, "checked_at": None, "built_at": None, "error": None, "busy": False, "log": []}
LOCK = threading.Lock()
OFFICIAL = {  # имя в кеше -> регэксп ассета релиза
    "rustdesk-latest-x86_64.exe": r"^rustdesk-[\d.]+-x86_64\.exe$",
    "rustdesk-latest-x86_64.deb": r"^rustdesk-[\d.]+-x86_64\.deb$",
    "rustdesk-latest-x86_64.dmg": r"^rustdesk-[\d.]+-x86_64\.dmg$",
    "rustdesk-latest-aarch64.dmg": r"^rustdesk-[\d.]+-aarch64\.dmg$",
    # ARM и другие дистрибутивы Linux (linux.sh / setup.ps1 берут отсюда, если GitHub недоступен)
    "rustdesk-latest-aarch64.exe": r"^rustdesk-[\d.]+-aarch64\.exe$",
    "rustdesk-latest-x86-sciter.exe": r"^rustdesk-[\d.]+-x86-sciter\.exe$",   # Windows 7/8 и 32-битные
    "rustdesk-latest-aarch64.deb": r"^rustdesk-[\d.]+-aarch64\.deb$",
    "rustdesk-latest-armv7-sciter.deb": r"^rustdesk-[\d.]+-armv7-sciter\.deb$",
    "rustdesk-latest-x86_64.rpm": r"^rustdesk-[\d.]+-0\.x86_64\.rpm$",
    "rustdesk-latest-aarch64.rpm": r"^rustdesk-[\d.]+-0\.aarch64\.rpm$",
    "rustdesk-latest-x86_64-suse.rpm": r"^rustdesk-[\d.]+-0\.x86_64-suse\.rpm$",
    "rustdesk-latest-aarch64-suse.rpm": r"^rustdesk-[\d.]+-0\.aarch64-suse\.rpm$",
    "rustdesk-latest-x86_64.pkg.tar.zst": r"^rustdesk-[\d.]+-0-x86_64\.pkg\.tar\.zst$",
}
PLISTS = "https://raw.githubusercontent.com/rustdesk/rustdesk/{tag}/src/platform/privileges_scripts/{f}.plist"

def log(msg):
    STATE["log"] = (STATE["log"] + [time.strftime("%Y-%m-%d %H:%M:%S ") + msg])[-40:]
    print("[builder]", msg, flush=True)

def opener():
    h = [urllib.request.ProxyHandler({"http": PROXY_URL, "https": PROXY_URL})] if PROXY_URL else []
    o = urllib.request.build_opener(*h); o.addheaders = [("User-Agent", "rds-panel")]; return o

def fetch(url, dst=None, timeout=60):
    with opener().open(url, timeout=timeout) as r:
        if dst is None: return r.read()
        with open(dst, "wb") as f: shutil.copyfileobj(r, f, 1 << 20)

def current_version():
    v = [p.name for p in CACHE.iterdir() if p.is_dir() and not p.name.endswith(".tmp")]
    return sorted(v)[-1] if v else None

def ensure_cache():
    """Скачать последний релиз в cache/<ver>, старые версии удалить."""
    rel = json.loads(fetch("https://api.github.com/repos/rustdesk/rustdesk/releases/latest", timeout=30))
    ver = rel["tag_name"].lstrip("v")
    if (CACHE / ver).is_dir():
        missing = [k for k in OFFICIAL if not (CACHE / ver / k).exists()]
        for local in missing:   # список OFFICIAL расширился — докачиваем в текущую версию
            a = next((a for a in rel["assets"] if re.match(OFFICIAL[local], a["name"])), None)
            if not a: log(f"в релизе {ver} нет {OFFICIAL[local]}"); continue
            log(f"докачиваю {a['name']} ({a['size'] // 1048576} МБ)")
            part = CACHE / ver / (local + ".part"); fetch(a["browser_download_url"], part, timeout=900)
            if part.stat().st_size != a["size"]: part.unlink(); raise RuntimeError(f"{a['name']}: размер не совпал")
            part.rename(CACHE / ver / local)
        return ver, False
    tmp = CACHE / (ver + ".tmp"); shutil.rmtree(tmp, ignore_errors=True); tmp.mkdir()
    for local, rx in OFFICIAL.items():
        a = next((a for a in rel["assets"] if re.match(rx, a["name"])), None)
        if not a: raise RuntimeError(f"в релизе {ver} нет {rx}")
        log(f"скачиваю {a['name']} ({a['size'] // 1048576} МБ)")
        fetch(a["browser_download_url"], tmp / local, timeout=900)
        if (tmp / local).stat().st_size != a["size"]: raise RuntimeError(f"{a['name']}: размер не совпал")
    for f in ("agent", "daemon"):
        fetch(PLISTS.format(tag=rel["tag_name"], f=f), tmp / f"{f}.plist")
    tmp.rename(CACHE / ver)
    for p in CACHE.iterdir():
        if p.name != ver: shutil.rmtree(p, ignore_errors=True); log(f"удалил старый кеш {p.name}")
    return ver, True

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode: raise RuntimeError(f"{cmd[0]}: {(r.stderr or r.stdout)[-600:]}")
    return r.stdout

_ST = Path(__file__).parent / "static"
NSIS_ART = [f"-DICON={_ST / 'rustdesk.ico'}", f"-DHDR={_ST / 'nsis-header.bmp'}", f"-DWEL={_ST / 'nsis-welcome.bmp'}"]

def build(ver):
    out = DIST / (ver + ".tmp"); shutil.rmtree(out, ignore_errors=True); out.mkdir()
    work = D / "work"; shutil.rmtree(work, ignore_errors=True); work.mkdir()
    vi = ".".join((ver.split(".") + ["0", "0", "0", "0"])[:4])
    for master in (True, False):
        sfx = "" if master else "-OTP"
        # Windows: небольшой exe (NSIS) — сам скачивает клиент с GitHub, иначе с RDS
        ps1 = work / f"setup{sfx}.ps1"; ps1.write_text(render("setup.ps1", master), encoding="ascii")
        nsi = work / f"setup{sfx}.nsi"; nsi.write_text(render("setup.nsi", master), encoding="utf-8-sig")
        cap = "Установка RustDesk" + ("" if master else " (только одноразовый пароль)")
        run(["makensis", "-V2", "-INPUTCHARSET", "UTF8", f"-DOUT={out}/RustDesk-Setup{sfx}.exe", f"-DPS1={ps1}", *NSIS_ART,
             f"-DCAPTION={cap}", f"-DRDVER={ver}", f"-DVIVER={vi}", str(nsi)])
        # macOS: .dmg с «Install RustDesk.command» (клиент качается с GitHub, иначе с RDS)
        md = work / f"dmg{sfx}"; md.mkdir()
        cmd = md / "Install RustDesk.command"; cmd.write_text(render("mac.sh", master), encoding="utf-8"); cmd.chmod(0o755)
        (md / "README.txt").write_text(
            "1. Дважды щёлкните «Install RustDesk.command».\n"
            "   Если macOS не даёт открыть: Системные настройки → Конфиденциальность и безопасность → «Всё равно открыть».\n"
            "2. Введите пароль от Mac.\n"
            "3. Разрешите RustDesk «Запись экрана» и «Универсальный доступ».\n", encoding="utf-8")
        run(["genisoimage", "-quiet", "-V", "RustDesk Setup", "-D", "-R", "-J", "-joliet-long", "-o", f"{out}/RustDesk-Setup{sfx}.dmg", str(md)])
        # Linux: официальный .deb + настройка в postinst
        dd = work / f"deb{sfx}"
        run(["dpkg-deb", "-R", str(CACHE / ver / "rustdesk-latest-x86_64.deb"), str(dd)])
        share = dd / "usr/share/rustdesk-neth"; share.mkdir(parents=True)
        pi = dd / "DEBIAN/postinst"
        if pi.exists(): shutil.move(pi, share / "postinst.orig"); (share / "postinst.orig").chmod(0o755)
        st = share / "setup.sh"; st.write_text(render("linux-setup.sh", master), encoding="utf-8"); st.chmod(0o755)
        pi.write_text('#!/bin/sh\nset -e\n[ -x /usr/share/rustdesk-neth/postinst.orig ] && /usr/share/rustdesk-neth/postinst.orig "$@"\n'
                      'if [ "$1" = configure ]; then /usr/share/rustdesk-neth/setup.sh || true; fi\nexit 0\n'); pi.chmod(0o755)
        ctl = dd / "DEBIAN/control"; t = ctl.read_text()
        ctl.write_text(re.sub(r"^Version: (.*)$", r"Version: \1+neth", t, flags=re.M))
        run(["dpkg-deb", "-Zxz", "-b", "--root-owner-group", str(dd), f"{out}/rustdesk-neth{sfx.lower()}_{ver}_amd64.deb"])
    shutil.rmtree(work, ignore_errors=True)
    for p in DIST.iterdir():
        if p.name not in (ver, out.name): shutil.rmtree(p, ignore_errors=True)
    shutil.rmtree(DIST / ver, ignore_errors=True); out.rename(DIST / ver)

def cycle(force=False):
    if not LOCK.acquire(blocking=False): return
    STATE["busy"] = True
    try:
        try:
            ver, new = ensure_cache()
        except Exception as e:  # GitHub недоступен — работаем с тем, что в кеше
            ver, new = current_version(), False
            log(f"проверка релиза не удалась: {e}")
            if not ver: raise
        STATE["checked_at"] = now()
        need = force or new or not (DIST / ver).is_dir() or STATE["version"] != ver
        if need:
            log(f"сборка установщиков для {ver}"); build(ver); STATE["built_at"] = now(); log("сборка готова")
        STATE["version"], STATE["error"] = ver, None
    except Exception as e:
        STATE["error"] = str(e)[:800]; log(f"ошибка: {e}")
    finally:
        STATE["busy"] = False; LOCK.release()

def loop():
    first = True
    while True:
        cycle(force=first); first = False
        time.sleep(CHECK_EVERY)

if not E("RDS_NO_BUILDER"): threading.Thread(target=loop, daemon=True).start()   # RDS_NO_BUILDER=1 — для служебных скриптов

# ---------------------------------------------------------------- auth
FAILS = {}
# ---------------------------------------------------------------- Redis (REDIS_URL): «в сети» и счётчики неудачных входов
# Без Redis (или если он недоступен) всё работает по-старому: счётчики в памяти, «в сети» по last_seen в БД.
REDIS_URL = E("REDIS_URL", "")
_R = {"c": None, "down_until": 0}

def rds():
    if not REDIS_URL or time.time() < _R["down_until"]: return None
    if _R["c"] is None:
        import redis
        _R["c"] = redis.Redis.from_url(REDIS_URL, socket_timeout=2, socket_connect_timeout=2, decode_responses=True)
    return _R["c"]

def _rcall(fn, default=None):
    r = rds()
    if r is None: return default
    try: return fn(r)
    except Exception as e:
        print("[redis] недоступен:", type(e).__name__, str(e)[:120], flush=True); _R["down_until"] = time.time() + 30; return default

def fail_count(ip):
    v = _rcall(lambda r: r.get("rds:fail:" + ip))
    if v is not None or rds(): return int(v or 0)
    return len([t for t in FAILS.get(ip, []) if t > now() - 900])

def fail_add(ip):
    if _rcall(lambda r: r.pipeline().incr("rds:fail:" + ip).expire("rds:fail:" + ip, 900).execute(), False) is False:
        FAILS[ip] = [t for t in FAILS.get(ip, []) if t > now() - 900] + [now()]

def fail_clear(ip):
    _rcall(lambda r: r.delete("rds:fail:" + ip)); FAILS.pop(ip, None)

def mark_seen(i):
    """Отметка «в сети». Возвращает True, если пора записать last_seen в БД (не чаще раза в 20 с на устройство)."""
    res = _rcall(lambda r: r.pipeline().setex("rds:seen:" + i, ONLINE_SEC, now()).set("rds:lsw:" + i, 1, nx=True, ex=20).execute())
    return True if res is None else bool(res[1])

def seen_map(ids):
    """{id: время последней отметки} из Redis (пусто без Redis)."""
    ids = list(ids)
    if not ids: return {}
    vals = _rcall(lambda r: r.mget(["rds:seen:" + i for i in ids]), None) or []
    return {i: int(v) for i, v in zip(ids, vals) if v}
def sign(v): return hmac.new(SECRET, v.encode(), hashlib.sha256).hexdigest()
SESSION_TTL = 12 * 3600
def make_cookie(user):
    u = get_user(user); ver = int((u["sess_ver"] if u else 0) or 0)
    v = f"{user}|{now() + SESSION_TTL}|{ver}"; return v + "|" + sign("s2|" + v)
def session_user(req):
    c = req.cookies.get("rds_session", "")
    try:
        u, exp, ver, s = c.rsplit("|", 3)
        if not (hmac.compare_digest(s, sign(f"s2|{u}|{exp}|{ver}")) and int(exp) > now()): return None
    except ValueError:
        return None
    r = get_user(u)
    if not r or int(r["sess_ver"] or 0) != int(ver): return None   # выход / смена пароля / 2FA завершают все сессии
    return r

def bump_sessions(username):
    with db() as c: c.execute("update users set sess_ver=coalesce(sess_ver,0)+1 where username=?", (username,))

# ---------------------------------------------------------------- журнал действий администраторов и подтверждение кодом 2FA
ELEV_TTL = 15 * 60
def admin_log(username, ip, action, target="", ok=1):
    try:
        with db() as c:
            c.execute("insert into admin_log(ts, username, ip, action, target, ok) values(?,?,?,?,?,?)", (now(), username, clip(ip, 60), clip(action, 80), clip(target, 300), int(ok)))
            c.execute("delete from admin_log where ts < ?", (now() - 365 * 86400,))
    except Exception as e:
        print("[adminlog]", e, flush=True)

def _ip(req): return req.client.host if req.client else ""

def stepup(req, action):
    """Опасное действие (задания ПО, питание, пользователи, права, настройки, AD, ключи агентов, установщик со входом).
    У администратора с 2FA — нужен код не старше ELEV_TTL (после входа с кодом окно уже открыто);
    при настройке admin_2fa_required — администратор без 2FA такие действия выполнить не может. Всё пишется в журнал."""
    u = session_user(req)
    target = req.url.path
    if u["totp_on"]:
        if int(u["elev_until"] or 0) < now():
            admin_log(u["username"], _ip(req), action, target, 0)
            raise HTTPException(403, {"need_elev": True, "msg": "Подтвердите действие кодом из приложения-аутентификатора"})
    elif setting("admin_2fa_required", "0") == "1":
        admin_log(u["username"], _ip(req), action, target, 0)
        raise HTTPException(403, "Для этого действия включите двухфакторную защиту (☰ → Двухфакторная защита)")
    admin_log(u["username"], _ip(req), action, target, 1)

# ---------------------------------------------------------------- TOTP (RFC 6238, 30 с, 6 цифр) — второй фактор входа в панель
def totp_new_secret(): return base64.b32encode(os.urandom(20)).decode().rstrip("=")
def _totp_at(secret, step):
    k = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(k, step.to_bytes(8, "big"), hashlib.sha1).digest(); o = h[-1] & 15
    return f"{(int.from_bytes(h[o:o + 4], 'big') & 0x7fffffff) % 1000000:06d}"
TOTP_RESYNC = 10   # ±10 шагов = ±5 мин: дальше — только через пару кодов подряд (RFC 6238, п. 6)

def totp_verify(u, code, wide=False):
    """Проверка кода с учётом ухода часов (сервер без интернета/NTP). Возвращает (шаг, None) — код принят;
    (0, сек) — код верен, но часы разошлись на «сек»: нужен СЛЕДУЮЩИЙ код с тем же смещением; (0, None) — неверно.
    Обычное окно — ±1 шаг вокруг запомненного смещения; оно же подстраивается при каждом входе.
    wide=True (включение 2FA со свежим секретом) — сразу ±5 мин."""
    sec = u["totp_secret"]; last = int(u["totp_last"] or 0); drift = int(u["totp_drift"] or 0)
    code = re.sub(r"\D", "", str(code or ""))
    if len(code) != 6 or not sec: return 0, None
    t = now() // 30
    def find(offs):
        for off in sorted(offs, key=lambda o: abs(o - drift)):
            st = t + off
            if st > last and hmac.compare_digest(_totp_at(sec, st), code): return off
        return None
    def accept(off):
        with db() as c: c.execute("update users set totp_last=?, totp_drift=?, totp_resync='' where username=?", (t + off, off, u["username"]))
        return t + off, None
    off = find(range(drift - 1, drift + 2))
    if off is None and wide: off = find(range(-TOTP_RESYNC, TOTP_RESYNC + 1))
    if off is not None: return accept(off)
    off = find(range(drift - TOTP_RESYNC, drift + TOTP_RESYNC + 1))   # скачок относительно запомненного смещения
    if off is None: return 0, None
    try: poff, pst = (int(x) for x in str(u["totp_resync"] or "").split(":"))
    except ValueError: poff, pst = None, 0
    if poff == off and 0 < t + off - pst <= 4: return accept(off)          # второй код подряд с тем же смещением
    with db() as c: c.execute("update users set totp_resync=? where username=?", (f"{off}:{t + off}", u["username"]))
    return 0, off * 30

def resync_msg(sec):
    return (f"Часы сервера и телефона расходятся примерно на {abs(sec)} с. Дождитесь СЛЕДУЮЩЕГО кода в приложении и введите его — "
            "панель подстроится. Лучше настроить на сервере точное время (NTP).")

def totp_check(secret, code, last_step=0):
    """Шаг (>0), если код верен (окно ±1 шаг) и не использовался раньше; иначе 0."""
    code = re.sub(r"\D", "", str(code or ""))
    if len(code) != 6 or not secret: return 0
    t = now() // 30
    for st in (t, t - 1, t + 1):
        if st > int(last_step or 0) and hmac.compare_digest(_totp_at(secret, st), code): return st
    return 0
def authed(req): return session_user(req) is not None

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

def host(req): return (req.headers.get("host") or "").split(":")[0].lower()
def is_admin_host(req): return host(req) in (ADMIN_HOST, "127.0.0.1", "localhost")
def is_client_host(req): return host(req) in (CLIENT_HOST, "127.0.0.1", "localhost")

@app.middleware("http")
async def security_headers(req: Request, call_next):
    r = await call_next(req)
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Strict-Transport-Security"] = "max-age=31536000"
    if is_admin_host(req):
        r.headers["X-Frame-Options"] = "DENY"; r.headers["Cache-Control"] = "no-store"
        # даже при XSS страница не отправит данные на чужой адрес и не подгрузит чужой скрипт
        r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                                                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        r.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=()"
    return r

# ---------------------------------------------------------------- API для клиентов RustDesk
async def body_json(req):
    try: return json.loads((await req.body())[:65536] or b"{}")
    except ValueError: return {}

ID_RX = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
def clip(v, n=200): return str(v or "")[:n]

def in_hbbs(i):
    try:
        c = sqlite3.connect(f"file:{HBBS_DB}?mode=ro", uri=True, timeout=5)
        r = c.execute("select 1 from peer where id=?", (i,)).fetchone(); c.close(); return bool(r)
    except sqlite3.Error:
        return False

@app.post("/api/heartbeat")
async def heartbeat(req: Request):
    j = await body_json(req); i = str(j.get("id", ""))
    if not ID_RX.match(i): return JSONResponse({})
    with db() as c: row = c.execute("select sysinfo_at from devices where id=?", (i,)).fetchone()
    if not row and not in_hbbs(i): return JSONResponse({})   # чужие/выдуманные ID не заводим
    if mark_seen(i) or not row: upsert(i, last_seen=now(), uuid=clip(j.get("uuid"), 100), **ip_fields(req))
    if not row or not row["sysinfo_at"]: return JSONResponse({"sysinfo": True})
    return JSONResponse({})

@app.post("/api/sysinfo")
async def sysinfo(req: Request):
    j = await body_json(req); i = str(j.get("id", ""))
    if not ID_RX.match(i): return PlainTextResponse("ID_NOT_FOUND")
    with db() as c: known = c.execute("select 1 from devices where id=?", (i,)).fetchone()
    if not known and not in_hbbs(i): return PlainTextResponse("ID_NOT_FOUND")
    upsert(i, hostname=clip(j.get("hostname")), username=clip(j.get("username")), os=clip(j.get("os")),
           version=clip(j.get("version"), 40), cpu=clip(j.get("cpu")), memory=clip(j.get("memory"), 40),
           sysinfo_at=now(), last_seen=now(), **ip_fields(req))
    mark_seen(i)
    return PlainTextResponse("SYSINFO_UPDATED")

@app.post("/api/sysinfo_ver")
async def sysinfo_ver(): return PlainTextResponse("")

@app.post("/api/rds/register")
async def register(req: Request):
    j = await body_json(req)
    i = str(j.get("id", ""))
    if not ID_RX.match(i): raise HTTPException(400, "bad id")
    with db() as c: known = c.execute("select 1 from devices where id=?", (i,)).fetchone()
    if not known:   # новый ПК: общий токен + час на привязку агента (его первый запрос получит ключ)
        if not REG_TOKEN or not hmac.compare_digest(str(j.get("token", "")), REG_TOKEN): raise HTTPException(403)
    else:           # уже известный: привязанный — только своим ключом (переустановка на том же ПК)
        agent_auth(j)
    master = bool(j.get("master"))
    # подробную ОС («windows / Windows 11 Pro - 11 (28000)») присылает сам RustDesk в /api/sysinfo — не затираем её
    # коротким «windows» установщика; sysinfo_at=NULL — при следующем heartbeat панель попросит RustDesk прислать данные заново
    with db() as c: row = c.execute("select os from devices where id=?", (i,)).fetchone()
    f = dict(hostname=clip(j.get("hostname")), username=clip(j.get("username")),
             master=int(master), password=clip(j.get("password"), 64) if master else "",
             installed_at=now(), source="installer", sysinfo_at=None, **ip_fields(req))
    if j.get("username"): f["inst_user"] = clip(j.get("username"), 120)
    # что сообщил сам установщик (локальный адрес сетевой карты и внешний через rd01/whoami) — точнее адреса запроса
    hw = hw_fields(j)
    if "want_master" in j: f["want_master"] = 1 if j.get("want_master") in (True, 1, "1", "true") else 0   # какой вариант скачали
    if not row or " / " not in (row["os"] or ""): f["os"] = clip(j.get("os"), 20)
    if not known: f["agent_bind_until"] = str(now() + 3600)
    upsert(i, **f); apply_hw(i, hw)
    return {"ok": True}

# ---------------------------------------------------------------- страница для клиентов (rd01)
def client_only(req):
    if not is_client_host(req): raise HTTPException(404)

def with_cookie_banner(html):
    return html.replace("</body>", (TPL / "cookie.html").read_text(encoding="utf-8") + "\n</body>", 1)

def latest_file(name):
    v = current_version()
    if not v or not (CACHE / v / name).exists(): raise HTTPException(503, "Клиент ещё скачивается на сервер, попробуйте через пару минут")
    return CACHE / v / name

SUMS = {}
@app.get("/dl/official/SHA256SUMS")
def dl_sums(req: Request):
    """SHA-256 файлов кеша: setup.ps1 принимает по ним клиент там, где Windows 7 не умеет проверить подпись."""
    client_only(req)
    v = current_version()
    if not v: raise HTTPException(503)
    out = []
    for name in OFFICIAL:
        f = CACHE / v / name
        if not f.exists(): continue
        k = (str(f), f.stat().st_size, f.stat().st_mtime)
        if SUMS.get(name, (None,))[0] != k:
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for b in iter(lambda: fh.read(1 << 20), b""): h.update(b)
            SUMS[name] = (k, h.hexdigest())
        out.append(f"{name} {SUMS[name][1]}")
    return PlainTextResponse("\n".join(out) + "\n", headers={"Cache-Control": "no-store"})

@app.get("/dl/official/{name}")
def dl_official(name: str, req: Request):
    client_only(req)
    if name not in OFFICIAL and name not in ("agent.plist", "daemon.plist"): raise HTTPException(404)
    v = current_version(); f = latest_file(name)
    nice = name.replace("latest", v) if "latest" in name else name
    return FileResponse(f, filename=nice)

def dist(name):
    v = STATE["version"] or current_version()
    if not v or not (DIST / v / name).exists(): raise HTTPException(503, "Установщики ещё собираются, попробуйте через пару минут")
    return DIST / v / name

@app.get("/download/{kind}")
def download(kind: str, req: Request, master: int = 1):
    client_only(req)
    sfx = "" if master else "-OTP"; v = STATE["version"] or current_version() or "0"
    names = {"windows": f"RustDesk-Setup{sfx}.exe", "mac": f"RustDesk-Setup{sfx}.dmg",
             "deb": f"rustdesk-neth{sfx.lower()}_{v}_amd64.deb"}
    if kind not in names: raise HTTPException(404)
    if kind == "mac":   # .pkg собирается на macOS-VM (/opt/RDS/macbuild), если есть — отдаём его вместо .dmg
        pkg = D / "macpkg" / f"RustDesk-Setup{sfx}.pkg"
        if pkg.exists(): return FileResponse(pkg, filename=pkg.name, media_type="application/octet-stream")
    return FileResponse(dist(names[kind]), filename=names[kind])

STATIC = Path(__file__).parent / "static"

@app.get("/favicon.svg")
def favicon_svg():
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=604800"})

@app.get("/favicon.ico")
def favicon_ico():
    return FileResponse(STATIC / "rustdesk.ico", media_type="image/x-icon", headers={"Cache-Control": "public, max-age=604800"})

@app.get("/privacy", response_class=HTMLResponse)
def privacy(req: Request):
    client_only(req)
    return HTMLResponse(with_cookie_banner((TPL / "privacy.html").read_text(encoding="utf-8").replace("{{RDS}}", RDS_HOST).replace("{{BASE}}", CLIENT_URL)))

@app.get("/whoami")
def whoami(req: Request):
    client_only(req)
    ip = req.headers.get("cf-connecting-ip") or req.client.host
    return PlainTextResponse(ip, headers={"Cache-Control": "no-store"})

@app.get("/update.ps1")
def update_ps1(req: Request):
    """Для агента обновления на Windows: тот же setup.ps1 (этапы prep/download/install)."""
    client_only(req); return PlainTextResponse(render("setup.ps1", True), headers={"Cache-Control": "no-store"})

@app.get("/hw.ps1")
def hw_ps1(req: Request):
    client_only(req); return PlainTextResponse(render("hw.ps1", True), headers={"Cache-Control": "no-store"})

@app.get("/hw.sh")
def hw_sh(req: Request):
    client_only(req); return PlainTextResponse(render("hw.sh", True), headers={"Cache-Control": "no-store"})

@app.get("/mac.sh")
def mac_sh(req: Request, master: int = 1):
    client_only(req); return PlainTextResponse(render("mac.sh", bool(master)))

@app.get("/linux.sh")
def linux_sh(req: Request, master: int = 1):
    """Универсальный установщик: Debian/Ubuntu/Astra, RHEL/CentOS/Fedora/РЕД ОС, SUSE, ALT, Arch; x86_64/aarch64/armv7."""
    client_only(req)
    head = render("linux.sh", bool(master))
    body = render("linux-setup.sh", bool(master)).split("\n", 3)[3]   # без shebang и комментариев
    return PlainTextResponse(head + "set +e\n" + body)

@app.get("/", response_class=HTMLResponse)
def index(req: Request):
    if is_admin_host(req) and host(req) == ADMIN_HOST:
        return admin_page(req)
    client_only(req)
    v = STATE["version"] or current_version() or "—"
    return HTMLResponse(with_cookie_banner((TPL / "client.html").read_text(encoding="utf-8")
                        .replace("{{VER}}", v).replace("{{RDS}}", RDS_HOST).replace("{{KEY}}", server_key())
                        .replace("{{API}}", API_URL).replace("{{BASE}}", CLIENT_URL)))

# ---------------------------------------------------------------- админка (rds)
def admin_only(req, need_auth=True):
    if not is_admin_host(req): raise HTTPException(404)
    if need_auth:
        u = session_user(req)
        if not u: raise HTTPException(401)
        if not u["is_admin"]: raise HTTPException(403, "Только для администратора")

def panel_user(req):
    """Любой вошедший в панель (администратор или пользователь)."""
    if not is_admin_host(req): raise HTTPException(404)
    u = session_user(req)
    if not u: raise HTTPException(401)
    return u

def setting(k, default=""):
    with db() as c: r = c.execute("select v from settings where k=?", (k,)).fetchone()
    return r["v"] if r and r["v"] is not None else default

PWR_DEF_MSG = "Компьютер будет {действие} через {время} по команде администратора. Сохраните работу."

def power_cfg():
    """Настройки выключения/перезагрузки из меню ☰: задержки в секундах и текст предупреждения."""
    def num(k):
        try: return max(0, min(86400, int(setting(k, "60"))))
        except ValueError: return 60
    return {"shutdown_delay": num("pwr_shutdown_delay"), "reboot_delay": num("pwr_reboot_delay"),
            "message": setting("pwr_message", "") or PWR_DEF_MSG}

def human_secs(s):
    s = int(s)
    if s <= 0: return "несколько секунд"
    if s < 60: return f"{s} с"
    return f"{s // 60} мин" + (f" {s % 60} с" if s % 60 else "")

def power_text(act, cfg):
    d = cfg[act + "_delay"]
    return cfg["message"].replace("{действие}", "выключен" if act == "shutdown" else "перезагружен").replace("{время}", human_secs(d))

# Права шаблонов. Действуют только на ПК групп пользователя; опасные действия — с кодом 2FA и в журнал.
PERM_KEYS = {"hw": "Железо и ПО ПК (просмотр, «обновить данные»)", "connect": "Подключение к ПК",
             "password": "Пароли клиентов RustDesk", "power": "Выключение, перезагрузка, Wake-on-LAN",
             "update": "Обновление RustDesk на ПК", "deploy": "Установка и удаление ПО из каталога"}
BUILTIN_ROLES = [("viewer", "Наблюдатель", ["hw"]), ("operator", "Оператор", ["hw", "connect", "password"]),
                 ("tech", "Техник", ["hw", "connect", "password", "power", "update", "deploy"]), ("admin", "Администратор", ["*"])]
with db() as c:
    for n, t, ps in BUILTIN_ROLES:
        c.execute("insert into roles(name, title, perms, builtin, created_at) values(?,?,?,1,?) on conflict do nothing", (n, t, json.dumps(ps), now()))
    c.execute("update roles set perms='[\"*\"]', title='Администратор', builtin=1 where name='admin'")

def roles_all():
    with db() as c: return {r["name"]: {"name": r["name"], "title": r["title"], "perms": json.loads(r["perms"] or "[]"), "builtin": bool(r["builtin"])}
                            for r in c.execute("select * from roles order by builtin desc, title")}

def _jl(v):
    try: x = json.loads(v or "[]"); return x if isinstance(x, list) else []
    except ValueError: return []

def user_role_names(u):
    with db() as c:
        g = [r[0] for r in c.execute("select role from groups where coalesce(role,'')<>'' and name in (select group_name from user_groups where username=?)", (u["username"],))]
    return {n for n in [u["role"] or "", *_jl(u["ad_roles"]), *g] if n}

def perms(u):
    """Права пользователя = объединение шаблонов (свой, групп панели, групп AD) + старые галочки «Подключение»/«Пароли».
    Тумблер «Прямое подключение» выключает всем (и админам) подключение и пароли."""
    direct = setting("direct_connect", "1") == "1"
    if u["is_admin"]:
        return {"admin": True, "direct": direct, **{k: True for k in PERM_KEYS}, "connect": direct, "password": direct}
    rs = roles_all(); ps = set()
    for n in user_role_names(u): ps |= set((rs.get(n) or {}).get("perms") or [])
    with db() as c:
        g = c.execute("select max(coalesce(can_connect,0)), max(coalesce(can_password,0)) from groups where name in "
                      "(select group_name from user_groups where username=?)", (u["username"],)).fetchone()
    if u["can_connect"] or (g and g[0]): ps.add("connect")
    if u["can_password"] or (g and g[1]): ps.add("password")
    out = {"admin": False, "direct": direct, **{k: k in ps for k in PERM_KEYS}}
    out["connect"] = direct and out["connect"]; out["password"] = direct and out["password"]
    return out

def need_perm(req, perm, device_id=None):
    """Вошедший пользователь с правом perm; для ПК — только из его групп (админ — любой)."""
    u = panel_user(req)
    if u["is_admin"]: return u
    if not perms(u).get(perm): raise HTTPException(403, "Нет права: " + PERM_KEYS.get(perm, perm))
    if device_id is not None and device_id not in {d["id"] for d in visible_devices(u)}: raise HTTPException(404)
    return u

def admin_page(req):
    if not authed(req): return HTMLResponse((TPL / "login.html").read_text(encoding="utf-8"))
    return HTMLResponse((TPL / "admin.html").read_text(encoding="utf-8"))

@app.post("/login")
async def login(req: Request):
    admin_only(req, need_auth=False)
    ip = req.client.host
    if fail_count(ip) >= 8: raise HTTPException(429, "Слишком много попыток, подождите 15 минут")
    j = await body_json(req)
    u = check_login(j.get("user"), j.get("password"))
    if u == "PENDING": raise HTTPException(403, "Пароль верный, но доступ ещё не одобрен администратором панели")
    ok = u is not None
    if not ok:
        fail_add(ip); time.sleep(1); raise HTTPException(403, "Неверный логин или пароль")
    if u["totp_on"]:
        if not str(j.get("otp") or "").strip():
            return JSONResponse({"detail": "Введите код из приложения-аутентификатора", "need_otp": True}, 401)
        st, rs = totp_verify(u, j.get("otp"))
        if rs is not None: return JSONResponse({"detail": resync_msg(rs), "need_otp": True, "resync": True}, 401)
        if not st:
            fail_add(ip); time.sleep(1); return JSONResponse({"detail": "Неверный код", "need_otp": True}, 401)
        with db() as c: c.execute("update users set elev_until=? where username=?", (now() + ELEV_TTL, u["username"]))
    fail_clear(ip)
    admin_log(u["username"], ip, "вход в панель" + (" (2FA)" if u["totp_on"] else ""))
    r = JSONResponse({"ok": True})
    with db() as c: c.execute("update users set last_login=? where username=?", (now(), u["username"]))
    r.set_cookie("rds_session", make_cookie(u["username"]), max_age=SESSION_TTL, httponly=True, secure=True, samesite="strict")
    return r

@app.post("/logout")
def logout(req: Request):
    u = session_user(req)
    if u and req.headers.get("x-rds") == "1": bump_sessions(u["username"])   # выход завершает сессии пользователя везде
    r = JSONResponse({"ok": True}); r.delete_cookie("rds_session"); return r

# ---------------------------------------------------------------- 2FA: своё включение/выключение, сброс администратором
@app.get("/admin/api/me/2fa")
def me_2fa(req: Request):
    u = panel_user(req); return {"on": bool(u["totp_on"])}

@app.post("/admin/api/me/2fa/setup")
def me_2fa_setup(req: Request):
    u = panel_user(req); csrf(req)
    if u["totp_on"]: raise HTTPException(400, "2FA уже включена")
    sec = totp_new_secret()
    with db() as c: c.execute("update users set totp_secret=?, totp_on=0 where username=?", (sec, u["username"]))
    from urllib.parse import quote
    label = quote(f"RDS ({ADMIN_HOST}):{u['username']}")
    uri = f"otpauth://totp/{label}?secret={sec}&issuer={quote('RDS ' + ADMIN_HOST)}&digits=6&period=30"
    svg = ""
    try:
        import io, segno
        b = io.BytesIO(); segno.make(uri, error="m").save(b, kind="svg", scale=5, border=2, dark="#000", light="#fff"); svg = b.getvalue().decode()
    except Exception as e:
        print("[2fa] QR:", e, flush=True)
    return {"secret": sec, "uri": uri, "qr_svg": svg}

@app.post("/admin/api/me/2fa/enable")
async def me_2fa_enable(req: Request):
    u = panel_user(req); csrf(req); j = await body_json(req)
    with db() as c: c.execute("update users set totp_drift=0, totp_resync='' where username=?", (u["username"],))
    u = get_user(u["username"])
    st, _ = totp_verify(u, j.get("code"), wide=True)
    if not st: raise HTTPException(400, "Неверный код — проверьте время на телефоне и введите новый код")
    with db() as c: c.execute("update users set totp_on=1 where username=?", (u["username"],))
    bump_sessions(u["username"])
    r = JSONResponse({"ok": True})
    r.set_cookie("rds_session", make_cookie(u["username"]), max_age=SESSION_TTL, httponly=True, secure=True, samesite="strict")
    print(f"[2fa] {u['username']}: включена", flush=True); return r

@app.post("/admin/api/me/2fa/disable")
async def me_2fa_disable(req: Request):
    u = panel_user(req); csrf(req); j = await body_json(req)
    if not u["totp_on"]: return {"ok": True}
    st, rs = totp_verify(u, j.get("code"))
    if rs is not None: raise HTTPException(409, resync_msg(rs))
    if not st: raise HTTPException(400, "Неверный код")
    with db() as c: c.execute("update users set totp_on=0, totp_secret='', totp_drift=0, totp_resync='' where username=?", (u["username"],))
    bump_sessions(u["username"])
    r = JSONResponse({"ok": True})
    r.set_cookie("rds_session", make_cookie(u["username"]), max_age=SESSION_TTL, httponly=True, secure=True, samesite="strict")
    print(f"[2fa] {u['username']}: выключена", flush=True); return r

@app.get("/api/time")
def server_time():
    """Время сервера — страница входа и окно 2FA сравнивают его с часами устройства."""
    return JSONResponse({"t": time.time()}, headers={"Cache-Control": "no-store"})

@app.get("/admin/api/me/elev")
def me_elev(req: Request):
    u = panel_user(req)
    return {"totp": bool(u["totp_on"]), "elevated": (not u["totp_on"]) or int(u["elev_until"] or 0) >= now()}

@app.post("/admin/api/me/elevate")
async def me_elevate(req: Request):
    """Код 2FA → на ELEV_TTL можно выполнять опасные действия без повторного ввода."""
    u = panel_user(req); csrf(req); j = await body_json(req); ip = _ip(req)
    if not u["totp_on"]: return {"ok": True}
    if fail_count(ip) >= 8: raise HTTPException(429, "Слишком много попыток, подождите 15 минут")
    st, rs = totp_verify(u, j.get("code"))
    if rs is not None: raise HTTPException(409, resync_msg(rs))
    if not st:
        fail_add(ip); time.sleep(1); admin_log(u["username"], ip, "подтверждение кодом", "", 0); raise HTTPException(400, "Неверный код")
    with db() as c: c.execute("update users set elev_until=? where username=?", (now() + ELEV_TTL, u["username"]))
    admin_log(u["username"], ip, "подтверждение кодом"); return {"ok": True, "until": now() + ELEV_TTL}

@app.get("/admin/api/adminlog")
def admin_log_list(req: Request):
    admin_only(req)
    with db() as c:
        return {"events": [dict(r) for r in c.execute("select ts, username, ip, action, target, ok from admin_log order by id desc limit 500")]}

@app.post("/admin/api/users/{name}/2fa-reset")
def user_2fa_reset(name: str, req: Request):
    """Потерян телефон: администратор выключает 2FA пользователю и завершает его сессии."""
    admin_only(req); csrf(req); stepup(req, "сброс 2FA пользователя")
    with db() as c: n = c.execute("update users set totp_on=0, totp_secret='' where username=?", (name,)).rowcount
    if not n: raise HTTPException(404)
    bump_sessions(name); print(f"[2fa] {name}: сброшена администратором", flush=True); return {"ok": True}

def csrf(req):
    if req.headers.get("x-rds") != "1": raise HTTPException(403)

def hbbs_peers():
    if not HBBS_DB.exists(): return {}
    try:
        c = sqlite3.connect(f"file:{HBBS_DB}?mode=ro", uri=True, timeout=5)
        out = {r[0]: (r[1], r[2]) for r in c.execute("select id, created_at, info from peer")}
        c.close(); return out
    except sqlite3.Error:
        return {}

@app.get("/admin/api/devices")
def devices(req: Request):
    u = panel_user(req); me = u["username"]; adm = bool(u["is_admin"])
    rows = [dict(r) for r in visible_devices(u)]; dg = dev_groups()
    with db() as c:
        favs = {r[0] for r in c.execute("select id from favs where username=?", (me,))}
        hwch = {r[0]: r[1] for r in c.execute("select id, max(ts) from hw_history where ts>? group by id", (now() - 14 * 86400,))}
    peers = hbbs_peers(); t = now(); res = []
    seen = seen_map(r["id"] for r in rows)
    isp = isp_on() and bool(ISP["orgs"])
    for r in rows:
        if seen.get(r["id"], 0) > (r["last_seen"] or 0): r["last_seen"] = seen[r["id"]]
        r["has_password"] = bool(r.pop("password")); r["online"] = bool(r["last_seen"] and t - r["last_seen"] < ONLINE_SEC)
        r["in_hbbs"] = r["id"] in peers; r["fav"] = r["id"] in favs; r["hw_changed"] = hwch.get(r["id"])
        r["has_hw"] = bool(r.get("hw_cpu") or r.get("cpu")); r.pop("printers", None); r.pop("scanners", None); r.pop("antivirus", None); r["sw_count"] = len(json.loads(r.pop("software", None) or "[]"))
        r["agent_ok"] = now() - int(r.get("agent_at") or 0) < 300
        r["agent_bound"] = bool(r.pop("agent_key_sha", "")); r.pop("agent_key_at", None); r.pop("agent_bind_until", None)
        r["inst_user"] = r.get("inst_user") or r.get("username") or ""
        r["groups"] = dg.get(r["id"], [])
        lu = str(r.get("logged_user") or ""); dom = lu.split("\\")[0] if "\\" in lu else ""
        r["domain"] = dom if dom and dom.lower() != str(r.get("hostname") or "").lower() else ""
        if isp:
            lip = r.get("last_ip") or ""
            r["isp"] = isp_name(r.get("ext_ip") or ("" if is_private(lip) else lip))
        # результат последней команды показываем ограниченное время: «выключается/перезагружается» — 10 мин
        # (дальше это уже не новость), остальное (обновление, ошибка, отмена) — сутки; в базе он остаётся
        if r.get("cmd_result") and not r.get("cmd"):
            age = t - int(r.get("cmd_at") or 0)
            if age > (600 if r["cmd_result"].startswith(("выключается", "перезагружается")) else 86400): r["cmd_result"] = ""
        res.append(r)
    known = {r["id"] for r in rows}
    for pid, (created, info) in (peers.items() if adm else []):
        if pid in known: continue
        try: ip = json.loads(info or "{}").get("ip", "").replace("::ffff:", "")
        except ValueError: ip = ""
        res.append({"id": pid, "source": "hbbs", "hostname": "", "os": "", "version": "", "online": False,
                    "installed_at": None, "created_at": created, "last_ip": ip, "has_password": False, "master": None,
                    "note": "", "in_hbbs": True})
    # у ПК в сети last_seen меняется с каждым heartbeat — сортировать их по нему нельзя (строки прыгали);
    # в сети — по имени, не в сети — по времени последнего появления
    res.sort(key=lambda r: (not r.get("fav"), not r["online"], r["source"] == "hbbs",
                            0 if r["online"] else -(r.get("last_seen") or r.get("installed_at") or 0),
                            (r.get("hostname") or "").lower(), r["id"]))
    return {"devices": res, "now": t, "latest": current_version() or ""}

@app.post("/admin/api/devices/{i}/wake")
def device_wake(i: str, req: Request):
    """Разбудить ПК (Wake-on-LAN). Работает для ПК в локальной сети сервера; MAC сообщает установщик."""
    need_perm(req, "power", i); csrf(req)
    with db() as c: r = c.execute("select mac, local_ip from devices where id=?", (i,)).fetchone()
    if not r or not r["mac"]: raise HTTPException(400, "MAC-адрес неизвестен — переустановите RustDesk новым установщиком")
    sent = wake_on_lan(r["mac"], r["local_ip"] or "")
    if not sent: raise HTTPException(500, "Не удалось отправить пакет")
    return {"ok": True, "mac": r["mac"], "sent": sent}

@app.get("/admin/api/devices/{i}/password")
def device_password(i: str, req: Request):
    u = panel_user(req)
    p = perms(u)
    if not p["password"]: raise HTTPException(403, "Прямое подключение выключено" if not p["direct"] else "Нет доступа к паролям — попросите администратора")
    if not u["is_admin"] and i not in {d["id"] for d in visible_devices(u)}: raise HTTPException(404)
    with db() as c: r = c.execute("select password from devices where id=?", (i,)).fetchone()
    if not r: raise HTTPException(404)
    return {"password": r["password"] or ""}

@app.post("/admin/api/devices/{i}/note")
async def device_note(i: str, req: Request):
    admin_only(req); csrf(req); j = await body_json(req)
    upsert(i, note=clip(j.get("note"), 500)); return {"ok": True}

@app.delete("/admin/api/devices/{i}")
def device_delete(i: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "удаление ПК")
    with db() as c: c.execute("delete from devices where id=?", (i,)); c.execute("delete from device_groups where id=?", (i,))
    return {"ok": True}

@app.get("/admin/api/status")
def status(req: Request):
    admin_only(req)
    v = STATE["version"] or current_version()
    files = sorted(p.name for p in (DIST / v).iterdir()) if v and (DIST / v).is_dir() else []
    files += sorted(p.name + " (macOS-VM)" for p in (D / "macpkg").glob("*.pkg"))
    return {**STATE, "files": files, "rds_host": RDS_HOST, "api": API_URL, "client_url": CLIENT_URL, "key": server_key()}

@app.post("/admin/api/devices/{i}/agent-reset")
def device_agent_reset(i: str, req: Request):
    """Сбросить привязку агента (переустановка ОС / замена ПК): следующий запрос агента в течение часа получит новый ключ."""
    admin_only(req); csrf(req); stepup(req, "сброс ключа агента")
    with db() as c:
        n = c.execute("update devices set agent_key_sha='', agent_key_at='', agent_bind_until=? where id=?", (str(now() + 3600), i)).rowcount
    if not n: raise HTTPException(404)
    print(f"[agent] {i}: привязка сброшена администратором", flush=True)
    return {"ok": True}

@app.post("/admin/api/rebuild")
def rebuild(req: Request):
    admin_only(req); csrf(req)
    threading.Thread(target=cycle, kwargs={"force": True}, daemon=True).start(); return {"ok": True}


# ---------------------------------------------------------------- аккаунт в клиенте RustDesk
def user_payload(u):
    return {"name": u["username"], "display_name": u["display_name"] or u["username"], "email": "", "note": u["note"] or "",
            "status": 1, "is_admin": bool(u["is_admin"]), "avatar": "", "verifier": ""}

def bearer_user(req):
    a = req.headers.get("authorization", "")
    if not a.lower().startswith("bearer "): return None
    t = hashlib.sha256(a[7:].strip().encode()).hexdigest()
    with db() as c:
        r = c.execute("select username, created_at from tokens where token_sha=?", (t,)).fetchone()
        if not r or r["created_at"] < now() - 90 * 86400: return None
        c.execute("update tokens set last_used=? where token_sha=?", (now(), t))
    return get_user(r["username"])

def need_user(req):
    u = bearer_user(req)
    if not u: raise HTTPException(401, "Требуется вход")
    return u

def page(req, items):
    try: cur = max(1, int(req.query_params.get("current", 1))); size = max(1, min(1000, int(req.query_params.get("pageSize", 100))))
    except ValueError: cur, size = 1, 100
    return {"total": len(items), "data": items[(cur - 1) * size: cur * size]}

@app.get("/api/login-options")
def login_options(): return []

@app.post("/api/login")
async def api_login(req: Request):
    ip = req.client.host
    if fail_count(ip) >= 8: return JSONResponse({"error": "Слишком много попыток, подождите 15 минут"}, 429)
    j = await body_json(req)
    u = check_login(j.get("username"), j.get("password"))
    if u == "PENDING": return JSONResponse({"error": "Доступ ещё не одобрен администратором панели"}, 403)
    if not u:
        fail_add(ip); time.sleep(1)
        return JSONResponse({"error": "Неверный логин или пароль"}, 401)
    fail_clear(ip)
    tok = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    with db() as c:
        c.execute("insert into tokens values(?,?,?,?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), u["username"], now(), now(),
                  clip(j.get("id"), 40), clip(j.get("uuid"), 100)))
        c.execute("update users set last_login=? where username=?", (now(), u["username"]))
    return {"type": "access_token", "access_token": tok, "user": user_payload(u)}

@app.post("/api/currentUser")
def api_current(req: Request): return user_payload(need_user(req))

@app.post("/api/logout")
def api_logout(req: Request):
    a = req.headers.get("authorization", "")
    if a.lower().startswith("bearer "):
        with db() as c: c.execute("delete from tokens where token_sha=?", (hashlib.sha256(a[7:].strip().encode()).hexdigest(),))
    return {}

def pid(i):
    """ID для списков клиента RustDesk (см. SPECIAL_IDS)."""
    if not SPECIAL_IDS: return i
    k = server_key()
    return f"{i}@{RDS_HOST}" + (f"?key={k}" if k else "")

# ---------------------------------------------------------------- IP-адреса устройств
# Из домашней сети RustDesk ходит на rds через роутер (hairpin NAT) — панель видит адрес роутера (HAIRPIN_IP),
# а не ПК. Поэтому: локальный IP сообщает установщик; внешний — установщик (через rd01/whoami, Cloudflare даёт
# настоящий адрес) и каждая отметка RustDesk с публичного адреса; отметка через hairpin = наш домашний внешний IP.
import ipaddress, socket
HAIRPIN_IP = E("HAIRPIN_IP", "192.168.0.1")
_HOME = {"ip": E("HOME_IP", ""), "at": 0}

def ip_ok(v):
    try: return str(ipaddress.ip_address(str(v).strip().replace("::ffff:", "")))
    except ValueError: return ""

def is_private(ip):
    try: a = ipaddress.ip_address(ip); return a.is_private or a.is_loopback or a.is_link_local
    except ValueError: return False

# ---------------------------------------------------------------- провайдер по внешнему IP (тумблер isp_lookup)
# Офлайн-база DB-IP «IP to ASN Lite» (CC BY 4.0, https://db-ip.com): панель скачивает её раз в месяц в PANEL_DIR/isp,
# без интернета работает последняя скачанная. IP клиентов во внешние сервисы не отправляются.
from array import array
import bisect, csv, gzip
ISP_DIR = D / "isp"
ISP = {"v4s": array("L"), "v4e": array("L"), "v4o": array("I"), "v6s": [], "v6e": [], "v6o": array("I"), "orgs": [],
       "file": "", "err": "", "busy": False, "at": 0}
_ISP_CACHE = {}

def isp_on(): return setting("isp_lookup", "0") == "1"

def _isp_load(path):
    rows4, rows6, orgs, idx = [], [], [], {}
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 4: continue
            org, asn = (row[3] or "").strip(), (row[2] or "").strip()
            label = f"{org} (AS{asn})" if org and asn and asn != "0" else (org or (f"AS{asn}" if asn and asn != "0" else ""))
            if not label: continue
            k = idx.get(label)
            if k is None: k = idx[label] = len(orgs); orgs.append(label)
            try: a, b = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
            except ValueError: continue
            (rows4 if a.version == 4 else rows6).append((int(a), int(b), k))
    rows4.sort(); rows6.sort()
    ISP.update(v4s=array("L", (r[0] for r in rows4)), v4e=array("L", (r[1] for r in rows4)), v4o=array("I", (r[2] for r in rows4)),
               v6s=[r[0] for r in rows6], v6e=[r[1] for r in rows6], v6o=array("I", (r[2] for r in rows6)),
               orgs=orgs, file=path.name, err="", at=int(time.time()))
    _ISP_CACHE.clear()
    print(f"[isp] база {path.name}: IPv4 {len(rows4)}, IPv6 {len(rows6)}, провайдеров {len(orgs)}", flush=True)

def isp_name(ip):
    """Провайдер (организация и номер AS) по IP; частный адрес — «локальная сеть»; нет базы или адреса — ''."""
    ip = ip_ok(ip or "")
    if not ip: return ""
    if is_private(ip): return "локальная сеть"
    if not ISP["orgs"]: return ""
    r = _ISP_CACHE.get(ip)
    if r is not None: return r
    a = ipaddress.ip_address(ip); n = int(a)
    s, e, o = (ISP["v4s"], ISP["v4e"], ISP["v4o"]) if a.version == 4 else (ISP["v6s"], ISP["v6e"], ISP["v6o"])
    i = bisect.bisect_right(s, n) - 1
    r = ISP["orgs"][o[i]] if i >= 0 and n <= e[i] else ""
    if len(_ISP_CACHE) > 50000: _ISP_CACHE.clear()
    _ISP_CACHE[ip] = r
    return r

def _isp_fetch():
    ISP_DIR.mkdir(parents=True, exist_ok=True)
    t = time.gmtime(); prev = (t.tm_year - 1, 12) if t.tm_mon == 1 else (t.tm_year, t.tm_mon - 1)
    for y, m in ((t.tm_year, t.tm_mon), prev):
        name = f"dbip-asn-lite-{y}-{m:02d}.csv.gz"
        if (ISP_DIR / name).exists(): return ISP_DIR / name
        tmp = ISP_DIR / (name + ".tmp")
        try:
            fetch(f"https://download.db-ip.com/free/{name}", tmp, timeout=300)
            with gzip.open(tmp, "rt", encoding="utf-8") as g:
                if "," not in g.readline(): raise ValueError("не CSV")
            tmp.rename(ISP_DIR / name)
            for old in ISP_DIR.glob("dbip-asn-lite-*.csv.gz"):
                if old.name != name: old.unlink()
            return ISP_DIR / name
        except Exception as ex:
            ISP["err"] = f"не удалось скачать базу провайдеров: {type(ex).__name__}"
            tmp.unlink(missing_ok=True)
    return None

def isp_refresh(force=False):
    if ISP["busy"]: return
    ISP["busy"] = True
    try:
        have = sorted(ISP_DIR.glob("dbip-asn-lite-*.csv.gz")) if ISP_DIR.exists() else []
        cur = have[-1] if have else None
        if force or not cur or time.time() - cur.stat().st_mtime > 32 * 86400:
            cur = _isp_fetch() or cur
        if cur and (cur.name != ISP["file"] or not ISP["orgs"]): _isp_load(cur)
    except Exception as ex:
        ISP["err"] = f"{type(ex).__name__}: {str(ex)[:150]}"
    finally:
        ISP["busy"] = False

def _isp_loop():
    time.sleep(5)
    while True:
        try:
            if isp_on(): isp_refresh()
        except Exception as ex: print("[isp]", type(ex).__name__, ex, flush=True)
        time.sleep(6 * 3600)

if not E("RDS_NO_BUILDER"): threading.Thread(target=_isp_loop, daemon=True).start()

def home_ip():
    """Внешний IP нашей сети (env HOME_IP или A-запись RDS_HOST, кеш 1 ч)."""
    if E("HOME_IP", ""): return E("HOME_IP", "")
    if time.time() - _HOME["at"] > 3600:
        _HOME["at"] = time.time()
        try:
            ip = socket.gethostbyname(RDS_HOST)
            if not is_private(ip): _HOME["ip"] = ip
        except OSError: pass
    return _HOME["ip"]

def ip_fields(req):
    """Поля IP для upsert по адресу запроса (heartbeat/sysinfo/register)."""
    ip = ip_ok((req.headers.get("cf-connecting-ip") if is_client_host(req) else "") or req.client.host)
    f = {"last_ip": ip}
    if not ip: return f
    if not is_private(ip): f["ext_ip"] = ip
    elif ip == HAIRPIN_IP:
        if home_ip(): f["ext_ip"] = home_ip()
    else: f["local_ip"] = ip            # ПК в одной сети с сервером без hairpin — видим его настоящий адрес
    return f

MAC_RX = re.compile(r"^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$", re.I)
def mac_ok(v):
    m = MAC_RX.match(str(v or "").strip())
    if not m or m.group(0).replace(":", "").replace("-", "").strip("0") == "": return ""
    return ":".join(x.lower() for x in m.groups())

def wake_on_lan(mac, local_ip=""):
    """Magic packet: 6×FF + 16×MAC, широковещательно на UDP 9 и 7 (и на broadcast /24 сети ПК, если она известна)."""
    pkt = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
    targets = {"255.255.255.255"}
    if local_ip and is_private(local_ip) and local_ip.count(".") == 3: targets.add(local_ip.rsplit(".", 1)[0] + ".255")
    if HAIRPIN_IP.count(".") == 3: targets.add(HAIRPIN_IP.rsplit(".", 1)[0] + ".255")
    sent = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
        so.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for t in sorted(targets):
            for port in (9, 7):
                try: so.sendto(pkt, (t, port)); sent.append(f"{t}:{port}")
                except OSError: pass
    return sent

HW_TRACK = {"hw_cpu": "Процессор", "gpu": "Видеокарта", "hw_ram": "Память", "disk": "Системный диск", "nic": "Сеть",
            "mac": "MAC", "printers": "Принтеры", "scanners": "Сканеры", "antivirus": "Антивирус", "pc_users": "Пользователи", "activation": "Активация Windows", "office": "MS Office",
            "board": "Материнская плата", "gpu_mem": "Видеопамять", "bt": "Bluetooth"}
ACT_STATUS = {"0": "Не активирована", "1": "Активирована", "2": "Льготный период (не активирована)", "3": "Льготный период (изменилось железо)",
              "4": "Льготный период (неподлинная)", "5": "Уведомления: не активирована", "6": "Продлённый льготный период"}

def activation_text(j):
    st = str(j.get("act_status") or "").strip()
    if st not in ACT_STATUS: return ""
    ch = clip(j.get("act_channel"), 40).strip(); kms = clip(j.get("act_kms"), 120).strip()
    try: days = int(float(j.get("act_grace") or 0)) // 1440
    except (TypeError, ValueError): days = 0
    parts = [ACT_STATUS[st]] + ([ch] if ch else []) + ([f"сервер {kms}"] if kms else [])
    if days and (st != "1" or ch in ("KMS", "Evaluation")): parts.append(f"осталось {days} дн.")
    return " · ".join(parts)

OFFICE_STATUS = {"0": "Не активирован", "1": "Активирован", "2": "Льготный период (не активирован)", "3": "Льготный период (изменилось железо)",
                 "4": "Льготный период (неподлинный)", "5": "Уведомления: не активирован", "6": "Продлённый льготный период",
                 "sub": "Подписка Microsoft 365 (лицензия в аккаунте)", "vnext": "Активирован (лицензия в учётной записи Microsoft)"}

def office_text(j):
    """«Office LTSC Standard 2024 · Активирован · KMS · сервер kms.local»; '' — Office не установлен."""
    name = clip(j.get("office_name"), 160).strip(); st = str(j.get("office_status") or "").strip()
    if not name and st not in OFFICE_STATUS: return ""
    ch = clip(j.get("office_channel"), 40).strip(); kms = clip(j.get("office_kms"), 120).strip()
    parts = [name or "Microsoft Office", OFFICE_STATUS.get(st, "статус неизвестен")] + ([ch] if ch and st != "sub" else []) + ([f"сервер {kms}"] if kms and st != "vnext" else [])
    return " · ".join(parts)

REDIRECTED_RX = re.compile(r"\((перенаправлено|redirected)\b", re.I)

def _printers(v):
    """JSON-строка от сборщика → нормализованный JSON-список (или '' если пусто/мусор)."""
    try: lst = json.loads(v) if isinstance(v, str) else v
    except ValueError: return ""
    out = []
    for p in (lst if isinstance(lst, list) else [])[:50]:
        if not isinstance(p, dict) or not str(p.get("name", "")).strip(): continue
        if REDIRECTED_RX.search(str(p["name"])): continue   # принтер ПК, С КОТОРОГО подключались (RDP/удалённый сеанс)
        t = p.get("type") if p.get("type") in ("usb", "network", "other") else "other"
        ip = clip(p.get("ip"), 120).strip(); mac = mac_ok(p.get("mac"))
        dflt = p.get("default")
        st = p.get("state") if p.get("state") in ("ok", "offline_mode", "disconnected", "problem") else ""
        out.append({"name": clip(p["name"], 120).strip(), "type": t, "ip": ip, "mac": mac, "default": None if dflt is None else bool(dflt), "state": st})
    out.sort(key=lambda x: (not x["default"], x["name"].lower()))
    return json.dumps(out, ensure_ascii=False) if out else "[]"

_GPU_VENDOR = re.compile(r"^(Intel( Corporation)?|NVIDIA( Corporation)?|Advanced Micro Devices,? Inc\.?|AMD|ATI Technologies Inc\.?|Microsoft|VMware,? Inc\.?)\s+", re.I)
_NIC_NOISE = re.compile(r"\b(Gigabit Ethernet Controller|Ethernet Controller|Ethernet Connection|Network Connection|Ethernet Adapter|"
                        r"Network Adapter|Wireless Network Adapter|Wireless LAN Adapter|Family Controller|Controller|Adapter|\d+MHz)\b", re.I)
def short_nic(v):
    """«Killer E2400 Gigabit Ethernet Controller» → «Killer E2400»; «Intel(R) Ethernet Controller (3) I225-V» → «Intel I225-V»;
    «Realtek PCIe GbE Family Controller» → «Realtek PCIe GbE»."""
    g = re.sub(r"\((R|TM|C)\)|®|™", "", str(v or ""), flags=re.I)
    g = re.sub(r"\(\d+\)", " ", g)
    g = re.sub(r"\b(Corporation|Corp\.?|Inc\.?|Co\.,? Ltd\.?)\b", " ", g, flags=re.I)
    g = " ".join(_NIC_NOISE.sub(" ", g).split()).strip(" -·")
    return g or " ".join(str(v or "").split())

def short_nic_line(line):
    """«Кабель · 1 Гбит/с · <название>» — сокращаем только последнюю часть (название сетевой карты)."""
    parts = str(line or "").split(" · ")
    if len(parts) >= 2 and not re.search(r"Гбит|Мбит|Кабель|Wi-Fi$", parts[-1]): parts[-1] = short_nic(parts[-1])
    return " · ".join(parts)

_BOARD_VENDOR = [(r"Micro-Star|^MSI\b", "MSI"), (r"ASUSTeK|^ASUS", "ASUS"), (r"Gigabyte|GIGA-BYTE", "Gigabyte"), (r"ASRock", "ASRock"),
                 (r"^Dell", "Dell"), (r"Hewlett|^HP\b", "HP"), (r"^LENOVO", "Lenovo"), (r"^Acer", "Acer"), (r"Biostar", "Biostar"),
                 (r"Supermicro", "Supermicro"), (r"^Intel", "Intel"), (r"^Apple", "Apple"), (r"Microsoft", "Microsoft"), (r"^QEMU", "QEMU")]
_BOARD_JUNK = re.compile(r"^(To Be Filled By O\.E\.M\.|Default string|Not Applicable|None|N/A|System Product Name|Base Board Product Name|Type2 - Board Product Name\d*)$", re.I)
def short_board(vendor, name):
    """«Micro-Star International Co., Ltd.» + «MAG B760M MORTAR WIFI (MS-7D25)» → «MSI MAG B760M MORTAR WIFI (MS-7D25)»."""
    v = " ".join(str(vendor or "").split()); n = " ".join(str(name or "").split())
    if _BOARD_JUNK.match(v): v = ""
    if _BOARD_JUNK.match(n): n = ""
    for rx, short in _BOARD_VENDOR:
        if re.search(rx, v, re.I): v = short; break
    else: v = re.sub(r",?\s*(Co\.,?\s*Ltd\.?|Inc\.?|Corporation|Corp\.?|Ltd\.?|GmbH|Technology|COMPUTER)\b\.?", "", v, flags=re.I).strip(" ,")
    if v and n.lower().startswith(v.lower()): v = ""
    n = re.sub(r"(\S)\(", r"\1 (", n)   # «PRO Z690-A DDR4(MS-7D25)» → «… DDR4 (MS-7D25)»
    return " ".join(x for x in (v, n) if x)[:160]

def _ru_plural(n, one, few, many):
    n = abs(int(n)); return one if n % 10 == 1 and n % 100 != 11 else few if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else many

def cpu_line(cpu, cores, threads):
    """«Intel(R) Core(TM) i5-7600K CPU @ 3.80GHz» + 4/4 → «… · 4 ядра / 4 потока»."""
    out = cpu or ""
    try: c = int(cores or 0); t = int(threads or 0)
    except ValueError: c = t = 0
    if c or t:
        bits = ([f"{c} {_ru_plural(c, 'ядро', 'ядра', 'ядер')}"] if c else []) + ([f"{t} {_ru_plural(t, 'поток', 'потока', 'потоков')}"] if t else [])
        out = (out + " · " if out else "") + " / ".join(bits)
    return out

def fmt_vram(b):
    try: b = float(b)
    except (TypeError, ValueError): return ""
    if b <= 0: return ""
    return f"{round(b / 2**30)} GB" if b >= 0.9 * 2**30 else f"{round(b / 2**20)} MB"

def gpu_with_mem(gpu, mem):
    """«Radeon RX 7700 XT» + «12GB» → «Radeon RX 7700 XT 12GB»; несколько карт — «; » в одном порядке."""
    g = [short_gpu(x) for x in str(gpu or "").split(";")]
    m = [re.sub(r"^(\d+)\s*(GB|MB)$", r"\1 \2", x.strip()) for x in str(mem or "").split(";")]   # старое «8GB» → «8 GB»
    if len(m) != len(g): return "; ".join(x for x in g if x)
    return "; ".join(f"{a} {b}" if a and b else a for a, b in zip(g, m) if a)

def short_gpu(v):
    """«Intel Corporation CoffeeLake-S GT2 [UHD Graphics 630]» → «UHD Graphics 630»; «Intel(R) UHD Graphics 630» → то же.
    Несколько видеокарт через «; »."""
    out = []
    for g in str(v or "").split(";"):
        g = g.strip()
        if not g: continue
        br = re.findall(r"\[([^\]]+)\]", g)
        if br and not (len(br) == 1 and br[0].upper() in ("AMD/ATI", "AMD")): g = br[-1]
        g = re.sub(r"\((R|TM|C)\)|®|™", "", g, flags=re.I)
        g = _GPU_VENDOR.sub("", " ".join(g.split())).strip()
        g = re.sub(r"\s+(Series|Graphics Adapter)$", "", g, flags=re.I)   # «Radeon RX 590 Series» → «Radeon RX 590»
        if g and g not in out: out.append(g)
    return "; ".join(out)

def _swlist(v):
    try: lst = json.loads(v) if isinstance(v, str) else v
    except ValueError: return "[]"
    out = [{"n": clip(a.get("n"), 160).strip(), "v": clip(a.get("v"), 60).strip(), "p": clip(a.get("p"), 120).strip()}
           for a in (lst if isinstance(lst, list) else [])[:600] if isinstance(a, dict) and str(a.get("n", "")).strip()]
    out.sort(key=lambda x: x["n"].lower())
    return json.dumps(out, ensure_ascii=False)

def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or (0,)

def _avlist(v):
    try: lst = json.loads(v) if isinstance(v, str) else v
    except ValueError: return ""
    out = [{"name": clip(a.get("name"), 120).strip(), "enabled": bool(a.get("enabled")),
            "uptodate": a.get("uptodate") if isinstance(a.get("uptodate"), bool) else None}
           for a in (lst if isinstance(lst, list) else [])[:20] if isinstance(a, dict) and str(a.get("name", "")).strip()]
    return json.dumps(out, ensure_ascii=False)

def hw_fields(j):
    """Железо, принтеры, пользователи и сеть от сборщика (установщик или hw.ps1/hw.sh). Поля RustDesk (cpu, memory) не трогаем."""
    f = {}
    t = lambda k, n=200: clip(j.get(k), n).strip()
    if t("cpu", 120): f["hw_cpu"] = " ".join(t("cpu", 120).split())
    if "gpu" in j: f["gpu"] = short_gpu(t("gpu", 300))
    if "gpu_mem" in j: f["gpu_mem"] = "; ".join(fmt_vram(x) for x in str(j.get("gpu_mem") or "").split(";")) if str(j.get("gpu_mem") or "").strip(" ;") else ""
    if "board_vendor" in j or "board_name" in j: f["board"] = short_board(t("board_vendor", 120), t("board_name", 120))
    try:
        ram = int(float(j.get("ram") or 0))
        if ram > 0: f["hw_ram"] = f"{round(ram / 1024 ** 3)} ГБ" if ram >= 1024 ** 3 else f"{ram // 1024 ** 2} МБ"
    except (TypeError, ValueError): pass
    if t("disk", 300): f["disk"] = t("disk", 300).replace(" GB (", " ГБ (")
    nt = t("nic_type", 20)
    if nt or t("nic_mbps", 20):
        try: sp = int(float(j.get("nic_mbps") or 0))
        except (TypeError, ValueError): sp = 0
        if nt == "wifi": nic = "Wi-Fi"
        elif nt == "ethernet" or sp:
            spd = (f"{sp // 1000} Гбит/с" if sp % 1000 == 0 else f"{sp / 1000:.1f} Гбит/с") if sp >= 1000 else (f"{sp} Мбит/с" if sp else "")
            nic = "Кабель" + (" · " + spd if spd else "")
        else: nic = "Другое"
        f["nic"] = nic + (" · " + short_nic(t("nic_name", 120)) if t("nic_name", 120) else "")
    if "printers" in j: f["printers"] = _printers(j.get("printers"))
    if "scanners" in j: f["scanners"] = _printers(j.get("scanners"))
    if "antivirus" in j: f["antivirus"] = _avlist(j.get("antivirus"))
    if "software" in j: f["software"] = _swlist(j.get("software")); f["sw_at"] = str(now())
    if activation_text(j): f["activation"] = activation_text(j)
    if "office_name" in j: f["office"] = office_text(j)   # новый сборщик прислал поле: пусто = Office удалили/нет
    if "office_detail" in j: f["office_detail"] = t("office_detail", 400)
    for k in ("cpu_cores", "cpu_threads"):
        if k in j:
            try: f[k] = str(max(0, min(4096, int(str(j.get(k) or "0").strip() or 0)))) if str(j.get(k) or "").strip() else ""
            except ValueError: pass
    if "ram_type" in j: f["ram_type"] = re.sub(r"[^A-Za-z0-9/ -]", "", t("ram_type", 40))
    if "bt_state" in j:
        st = str(j.get("bt_state") or ""); nm = re.sub(r"\((R|TM)\)|®|™", "", t("bt_name", 120)).strip()
        f["bt"] = {"ok": f"{nm or 'адаптер'} · включён", "disabled": f"{nm or 'адаптер'} · отключён", "error": f"{nm or 'адаптер'} · ошибка драйвера",
                   "none": "нет адаптера"}.get(st, "")
    if "users" in j: f["pc_users"] = t("users", 400)
    if "logged_user" in j: f["logged_user"] = t("logged_user", 120)
    lip, eip = ip_ok(j.get("local_ip")), ip_ok(j.get("ext_ip"))
    if lip and is_private(lip): f["local_ip"] = lip
    if eip and not is_private(eip): f["ext_ip"] = eip
    if mac_ok(j.get("mac")): f["mac"] = mac_ok(j.get("mac"))
    if any(k in f for k in ("hw_cpu", "hw_ram", "disk", "nic", "gpu")): f["hw_at"] = str(now())
    return f

LIST_FIELDS = ("printers", "scanners", "antivirus")
def _list_summary(field, text):
    """Список (JSON) → множество строк для сравнения и истории: без служебных полей (по умолчанию, MAC из ARP)."""
    try: lst = json.loads(text or "[]")
    except ValueError: return set()
    out = set()
    for a in lst if isinstance(lst, list) else []:
        if not isinstance(a, dict): continue
        if field == "antivirus": out.add(f"{a.get('name')}: {'вкл' if a.get('enabled') else 'выкл'}")
        else:
            conn = {"usb": "USB", "network": "сеть", "other": "другое"}.get(a.get("type"), "другое")
            out.add(f"{a.get('name')} ({conn}{', ' + a['ip'] if a.get('ip') else ''})")
    return out

def _merge_list(field, old_text, new_text):
    """MAC и «по умолчанию», которых нет в новом списке (ARP пуст / сбор от SYSTEM), берём из прежнего."""
    try: old = {a["name"]: a for a in json.loads(old_text or "[]")}; new = json.loads(new_text or "[]")
    except (ValueError, KeyError, TypeError): return new_text
    for a in new:
        o = old.get(a.get("name"))
        if a.get("default") is None: a["default"] = bool(o.get("default")) if o else False
        if o and not a.get("mac") and o.get("mac") and o.get("ip") == a.get("ip"): a["mac"] = o["mac"]
    new.sort(key=lambda x: (not x.get("default"), str(x.get("name", "")).lower()))
    return json.dumps(new, ensure_ascii=False)

def apply_hw(i, f):
    """Записать данные сборщика; изменения отслеживаемых полей (не первое заполнение) — в hw_history."""
    if not f: return []
    changes = []
    with db() as c:
        r = c.execute("select * from devices where id=?", (i,)).fetchone()
        if r:
            keys = r.keys()
            for k in ("printers", "scanners"):
                if k in f and k in keys: f[k] = _merge_list(k, r[k], f[k])
            for k, label in HW_TRACK.items():
                if k in f and k in keys:
                    old = r[k] or ""
                    if k in LIST_FIELDS:
                        if not old: continue
                        a, b = _list_summary(k, old), _list_summary(k, f[k])
                        if a != b:
                            gone, came = sorted(a - b), sorted(b - a)
                            changes.append((k, "; ".join(gone) or "—", "; ".join(came) or "—"))
                    elif old and f[k] != old: changes.append((k, old, f[k]))
            for k, old, new in changes:
                c.execute("insert into hw_history(id, ts, field, old, new) values(?,?,?,?,?)", (i, now(), k, old, new))
    upsert(i, **f)
    if changes: print(f"[hw] {i}: изменилось {[k for k, _, _ in changes]}", flush=True)
    return [k for k, _, _ in changes]

@app.post("/api/rds/hwinfo")
async def hwinfo(req: Request):
    """Обновить железо/IP/MAC уже установленного ПК без переустановки RustDesk (команда «обновить данные»)."""
    j = await body_json(req)
    i = str(j.get("id", ""))
    if not ID_RX.match(i): raise HTTPException(400, "bad id")
    with db() as c: known = c.execute("select 1 from devices where id=?", (i,)).fetchone()
    if not known: raise HTTPException(404, "ПК с таким ID нет в панели — установите RustDesk с rd01")
    i, nk = agent_auth(j, bind=True)
    f = hw_fields(j); f.update({k: v for k, v in ip_fields(req).items() if k == "ext_ip" and "ext_ip" not in f})
    ch = apply_hw(i, f)
    threading.Thread(target=ad_person, args=(i,), daemon=True).start()
    return {"ok": True, "updated": sorted(f), "changed": ch, **({"akey_new": nk} if nk else {})}

def ad_person(i):
    """ПК в домене (вошёл ДОМЕН\\user, домен ≠ имя ПК) и панель введена в AD/FreeIPA → displayName пользователя в person_ad."""
    try:
        with db() as c: r = c.execute("select hostname, logged_user, inst_user, username from devices where id=?", (i,)).fetchone()
        if not r: return
        lu = str(r["logged_user"] or "")
        if "\\" not in lu or lu.split("\\")[0].lower() == str(r["hostname"] or "").lower(): return
        cfg = ad_cfg()
        if cfg.get("enabled") != "1" or not cfg.get("url"): return
        found = ad_lookup(cfg, lu)
        if found and found[2]: upsert(i, person_ad=clip(found[2], 120))
    except Exception as e:
        print(f"[ad] имя пользователя ПК {i}: {e}", flush=True)

@app.get("/admin/api/devices/{i}/hw")
def device_hw(i: str, req: Request):
    """Окно «Hardware»: железо, сеть, принтеры, пользователи и история изменений."""
    need_perm(req, "hw", i)
    with db() as c:
        r = c.execute("select * from devices where id=?", (i,)).fetchone()
        if not r: raise HTTPException(404)
        hist = [{"ts": h["ts"], "field": HW_TRACK.get(h["field"], h["field"]),
                 "old": short_nic_line(h["old"]) if h["field"] == "nic" else h["old"], "new": short_nic_line(h["new"]) if h["field"] == "nic" else h["new"]}
                for h in c.execute("select * from hw_history where id=? order by ts desc limit 50", (i,))]
    d = dict(r)
    try: pr = json.loads(d.get("printers") or "[]")
    except ValueError: pr = []
    try: sc = json.loads(d.get("scanners") or "[]")
    except ValueError: sc = []
    try: av = json.loads(d.get("antivirus") or "[]")
    except ValueError: av = []
    lip = d.get("last_ip") or ""
    return {"id": i, "isp": isp_name(d.get("ext_ip") or ("" if is_private(lip) else lip)) if isp_on() else "",
            "hostname": d.get("hostname") or "", "os": d.get("os") or "",
            "cpu": cpu_line(d.get("hw_cpu") or d.get("cpu") or "", d.get("cpu_cores"), d.get("cpu_threads")), "gpu": gpu_with_mem(d.get("gpu") or "", d.get("gpu_mem") or ""), "board": d.get("board") or "", "ram": (d.get("hw_ram") or d.get("memory") or "") + (f" ({d['ram_type']})" if d.get("ram_type") and (d.get("hw_ram") or d.get("memory")) else ""),
            "disk": d.get("disk") or "", "nic": short_nic_line(d.get("nic") or ""), "mac": d.get("mac") or "", "local_ip": d.get("local_ip") or "",
            "ext_ip": d.get("ext_ip") or "", "users": d.get("pc_users") or "", "logged_user": d.get("logged_user") or "",
            "printers": pr, "scanners": sc, "antivirus": av, "activation": d.get("activation") or "", "bt": d.get("bt") or "", "office": d.get("office") or "", "office_detail": d.get("office_detail") or "", "hw_at": int(d.get("hw_at") or 0) or None, "history": hist,
            "from_rustdesk": not d.get("hw_cpu"),
            "agent_bound": bool(r["agent_key_sha"]), "agent_bind_open": int(r["agent_bind_until"] or 0) > now(),
            "cmd_win": f"iex ((New-Object Net.WebClient).DownloadString('{CLIENT_URL}/hw.ps1'))",
            "cmd_unix": f"curl -fsSL {CLIENT_URL}/hw.sh | sudo sh"}

# ---------------------------------------------------------------- обновление RustDesk по кнопке из панели
# Кнопка ставит devices.cmd='update'; агент на ПК (задание/таймер, раз в 5 мин) спрашивает /api/rds/poll,
# получает команду (cmd → 'running'), обновляет RustDesk и сообщает /api/rds/cmdresult.
def _ak_sha(k): return hashlib.sha256(("rds-agent-key:" + k).encode()).hexdigest()

def agent_strict(): return setting("agent_key_strict", "0") == "1"

def agent_auth(j, bind=False):
    """Агент ПК → панель. Привязанный ПК (agent_key_sha) — только своим ключом akey, общий токен не принимается.
    Не привязанный — общим REG_TOKEN (он есть в публичных скриптах), и если агент умеет хранить ключ (ak=1)
    и bind=True, панель выдаёт ему новый ключ (возвращается вторым значением, агент сохраняет его из akey_new).
    Строгий режим (настройка agent_key_strict): без ключа — только ПК с открытым окном привязки
    (новая установка или «Разрешить привязку агента» в панели)."""
    i = str(j.get("id", ""))
    if not ID_RX.match(i): raise HTTPException(400, "bad id")
    ak = str(j.get("akey") or "")
    with db() as c: r = c.execute("select agent_key_sha, agent_bind_until from devices where id=?", (i,)).fetchone()
    if r and r["agent_key_sha"]:
        if ak and hmac.compare_digest(_ak_sha(ak), r["agent_key_sha"]): return i, None
        print(f"[agent] {i}: неверный ключ агента", flush=True); raise HTTPException(403, "bad agent key")
    if not REG_TOKEN or not hmac.compare_digest(str(j.get("token", "")), REG_TOKEN): raise HTTPException(403)
    if not r: return i, None
    open_win = int(r["agent_bind_until"] or 0) > now()
    if agent_strict() and not open_win: raise HTTPException(403, "agent not bound")
    if bind and j.get("ak") in (1, True, "1", "true"):
        k = secrets_token(32)
        with db() as c:
            n = c.execute("update devices set agent_key_sha=?, agent_key_at=?, agent_bind_until='' where id=? and coalesce(agent_key_sha,'')=''",
                          (_ak_sha(k), str(now()), i)).rowcount
        if n: print(f"[agent] {i}: агент привязан (выдан ключ)", flush=True); return i, k
        raise HTTPException(403, "bad agent key")   # параллельный запрос успел привязать
    return i, None

def _client_auth(j): return agent_auth(j)[0]

@app.post("/api/rds/poll")
async def rds_poll(req: Request):
    j = await body_json(req); i, nk = agent_auth(j, bind=True)
    r = await _rds_poll(i, j)
    if nk: r = {**(r or {}), "akey_new": nk}
    return r

async def _rds_poll(i, j):
    rdv = clip(j.get("rdv"), 40).strip()   # версия RustDesk от агента: sysinfo шлёт только клиент, подключённый к серверу
    if re.fullmatch(r"\d+(\.\d+){1,3}", rdv):
        with db() as c: c.execute("update devices set version=? where id=? and coalesce(version,'')<>?", (rdv, i, rdv))
    ver = {"hwv_win": HWV_WIN, "hwv_unix": HWV_UNIX}   # агент обновит сборщик, если его версия другая
    with db() as c:
        r = c.execute("select cmd, cmd_at from devices where id=?", (i,)).fetchone()
        if not r: return {}
        c.execute("update devices set agent_at=? where id=?", (str(now()), i))
        cmd, at = r["cmd"] or "", int(r["cmd_at"] or 0)
        if cmd == "running" and now() - at > 1800:      # агент пропал посреди обновления
            c.execute("update devices set cmd='', cmd_result=? where id=?", ("ошибка: обновление не завершилось за 30 мин", i)); return ver
        if cmd in ("shutdown", "reboot"):
            c.execute("update devices set cmd='', cmd_at=? where id=?", (str(now()), i))
            pc = power_cfg()   # задержка и текст из меню ☰ (строки — агент на sh разбирает JSON sed-ом)
            return {"cmd": cmd, "delay": str(pc[cmd + "_delay"]), "msg_b64": _b64(power_text(cmd, pc))}
        if cmd == "hw":   # «Обновить данные» из карточки Hardware: агент сразу запускает сбор
            c.execute("update devices set cmd='', cmd_at=? where id=?", (str(now()), i))
            return {"cmd": "hw", **ver}
        if cmd != "update":
            job = _next_job(c, i)
            return {"job": job, **ver} if job else ver
        c.execute("update devices set cmd='running', cmd_at=? where id=?", (str(now()), i))
    return {"cmd": "update", "version": current_version() or ""}

@app.post("/api/rds/cmdresult")
async def rds_cmdresult(req: Request):
    j = await body_json(req); i = _client_auth(j)
    ver = clip(j.get("version"), 40).strip(); ok = bool(j.get("ok")); act = str(j.get("action") or "update")
    if act in ("shutdown", "reboot"):
        d = power_cfg()[act + "_delay"]   # «через N с» читает обратный отсчёт в панели
        res = {"shutdown": "выключается", "reboot": "перезагружается"}[act] + f" (через {d} с)"
        upsert(i, cmd="", cmd_at=str(now()), cmd_result=res); print(f"[power] {i}: {act}", flush=True); return {"ok": True}
    res = f"обновлено до {ver}" if ok else "ошибка: " + (clip(j.get("msg"), 200) or "неизвестно")
    f = {"cmd": "", "cmd_at": str(now()), "cmd_result": res}
    if ok and ver: f["version"] = ver
    upsert(i, **f)
    print(f"[update] {i}: {res}", flush=True)
    return {"ok": True}

@app.post("/admin/api/devices/{i}/update")
def device_update(i: str, req: Request):
    need_perm(req, "update", i); csrf(req); stepup(req, "обновление RustDesk на ПК")
    with db() as c:
        r = c.execute("select version, agent_at from devices where id=?", (i,)).fetchone()
        if not r: raise HTTPException(404)
        c.execute("update devices set cmd='update', cmd_at=?, cmd_result='' where id=?", (str(now()), i))
    agent = int(r["agent_at"] or 0)
    return {"ok": True, "latest": current_version(), "agent_ok": now() - agent < 300,
            "note": "" if now() - agent < 300 else "агент на этом ПК не отвечал последние 5 мин — задание выполнится, когда он появится (на старых установках выполните команду обновления данных от администратора)"}

@app.post("/admin/api/devices/{i}/power")
async def device_power(i: str, req: Request):
    """Выключить / перезагрузить ПК: команда агенту (заберёт в течение минуты)."""
    need_perm(req, "power", i); csrf(req); stepup(req, "выключение/перезагрузка ПК"); j = await body_json(req)
    act = str(j.get("action") or "")
    if act not in ("shutdown", "reboot"): raise HTTPException(400, "action: shutdown или reboot")
    with db() as c:
        r = c.execute("select agent_at from devices where id=?", (i,)).fetchone()
        if not r: raise HTTPException(404)
        c.execute("update devices set cmd=?, cmd_at=?, cmd_result='' where id=?", (act, str(now()), i))
    agent = int(r["agent_at"] or 0)
    return {"ok": True, "agent_ok": now() - agent < 300,
            "note": "" if now() - agent < 300 else "агент на этом ПК давно не отвечал — команда выполнится, когда он появится"}

@app.post("/admin/api/devices/{i}/update/cancel")
def device_update_cancel(i: str, req: Request):
    need_perm(req, "update", i); csrf(req); upsert(i, cmd="", cmd_result="отменено"); return {"ok": True}

@app.get("/admin/api/devices/{i}/software")
def device_software(i: str, req: Request):
    need_perm(req, "hw", i)
    with db() as c: r = c.execute("select hostname, software, sw_at from devices where id=?", (i,)).fetchone()
    if not r: raise HTTPException(404)
    try: sw = json.loads(r["software"] or "[]")
    except ValueError: sw = []
    return {"id": i, "hostname": r["hostname"] or "", "software": sw, "sw_at": int(r["sw_at"] or 0) or None,
            "cmd_win": f"iex ((New-Object Net.WebClient).DownloadString('{CLIENT_URL}/hw.ps1'))", "cmd_unix": f"curl -fsSL {CLIENT_URL}/hw.sh | sudo sh"}

@app.get("/admin/api/software")
def software_inventory(req: Request):
    """Вкладка «ПО»: сводка установленного ПО по всем ПК — программа + ОС → версии и компьютеры."""
    admin_only(req)
    items, no_data = {}, []
    with db() as c: rows = c.execute("select id, hostname, os, software, sw_at, source from devices").fetchall()
    for r in rows:
        if r["source"] == "hbbs": continue
        try: sw = json.loads(r["software"] or "[]")
        except ValueError: sw = []
        if not sw and not str(r["sw_at"] or "").strip("0 "):
            no_data.append({"id": r["id"], "hostname": r["hostname"] or ""}); continue
        plat = dev_platform(r["os"])
        for a in sw if isinstance(sw, list) else []:
            n = str((a or {}).get("n") or "").strip()
            if not n: continue
            it = items.setdefault((plat, n), {"n": n, "p": str(a.get("p") or ""), "plat": plat, "versions": {}, "devices": []})
            v = str(a.get("v") or "")
            it["versions"][v] = it["versions"].get(v, 0) + 1
            it["devices"].append({"id": r["id"], "hostname": r["hostname"] or "", "v": v})
    out = sorted(items.values(), key=lambda x: (-len(x["devices"]), x["n"].lower()))
    return {"items": out, "no_data": no_data,
            "cmd_win": f"iex ((New-Object Net.WebClient).DownloadString('{CLIENT_URL}/hw.ps1'))", "cmd_unix": f"curl -fsSL {CLIENT_URL}/hw.sh | sudo sh"}

@app.post("/admin/api/devices/{i}/net")
async def device_net(i: str, req: Request):
    """Ручная правка MAC/локального IP из админки (пусто — стереть)."""
    admin_only(req); csrf(req); j = await body_json(req)
    f = {}
    if "mac" in j:
        m = str(j["mac"] or "").strip()
        if m and not mac_ok(m): raise HTTPException(400, "MAC в формате aa:bb:cc:dd:ee:ff")
        f["mac"] = mac_ok(m) if m else ""
    if "local_ip" in j:
        ip = str(j["local_ip"] or "").strip()
        if ip and not (ip_ok(ip) and is_private(ip)): raise HTTPException(400, "Локальный IP — адрес частной сети, например 192.168.0.10")
        f["local_ip"] = ip_ok(ip) if ip else ""
    if f: upsert(i, **f)
    return {"ok": True, **f}

def user_groups(c, name):
    return [r[0] for r in c.execute("select group_name from user_groups where username=? order by group_name", (name,))]

def set_user_groups(c, name, groups):
    c.execute("delete from user_groups where username=?", (name,))
    for g in groups:
        c.execute("insert or ignore into groups(name, created_at) values(?,?)", (g, now()))
        c.execute("insert or ignore into user_groups(username, group_name) values(?,?)", (name, g))

def clean_groups(v):
    """Список групп из запроса: список строк или строка через запятую."""
    if isinstance(v, str): v = v.split(",")
    out = []
    for g in (v or [])[:100]:
        g = clip(g, 60).strip()
        if g and GROUP_RX.match(g) and g not in out: out.append(g)
    return out

def visible_devices(u):
    with db() as c:
        if u["is_admin"]: return c.execute("select * from devices").fetchall()
        return c.execute("select * from devices where owner=? or id in (select id from device_groups where group_name in "
                         "(select group_name from user_groups where username=?))", (u["username"], u["username"])).fetchall()

def dev_groups():
    """{ID: [группы]} — все группы компьютеров."""
    out = {}
    with db() as c:
        for i, g in c.execute("select id, group_name from device_groups order by group_name"): out.setdefault(i, []).append(g)
    return out

def set_dev_groups(i, groups, c=None):
    """Полный список групп компьютера; devices.group_name = первая (RustDesk API знает только одну)."""
    groups = sorted({g for g in (str(x).strip() for x in groups) if g and GROUP_RX.match(g)}, key=str.lower)
    def go(c):
        c.execute("delete from device_groups where id=?", (i,))
        for g in groups:
            c.execute("insert into groups(name, created_at) values(?,?) on conflict do nothing", (g, now()))
            c.execute("insert into device_groups(id, group_name) values(?,?) on conflict do nothing", (i, g))
        c.execute("update devices set group_name=? where id=?", (groups[0] if groups else "", i))
    if c is not None: go(c)
    else:
        with db() as c2: go(c2)
    return groups

def sync_primary_group(c, ids=None):
    """После массовых изменений групп: devices.group_name = первая группа компьютера (или '')."""
    q = "update devices d set group_name=coalesce((select min(group_name) from device_groups g where g.id=d.id), '')"
    if ids is None: c.execute(q)
    else:
        for i in ids: c.execute(q + " where d.id=?", (i,))

@app.get("/api/users")
def api_users(req: Request):
    u = need_user(req)
    with db() as c:
        if u["is_admin"]: rows = c.execute("select * from users order by username").fetchall()
        else:
            rows = c.execute("""select * from users where username=? or username in (select username from user_groups
                                where group_name in (select group_name from user_groups where username=?)) order by username""",
                             (u["username"], u["username"])).fetchall()
    return page(req, [user_payload(r) for r in rows])

@app.get("/api/peers")
def api_peers(req: Request):
    u = need_user(req)
    items = [{"id": pid(r["id"]), "info": {"username": r["username"] or "", "os": r["os"] or "", "device_name": r["hostname"] or ""},
              "status": 1, "user": r["owner"] or "", "user_name": r["owner"] or "", "device_group_name": r["group_name"] or "", "note": r["note"] or ""}
             for r in visible_devices(u)]
    return page(req, items)

@app.get("/api/device-group/accessible")
def api_groups(req: Request):
    u = need_user(req)
    dg = dev_groups(); names = sorted({g for r in visible_devices(u) for g in dg.get(r["id"], [])})
    return page(req, [{"name": n} for n in names])

# адресная книга (старый формат RustDesk: одна книга на пользователя, хранится как есть)
FAV_TAG = "⭐ Избранное"

def _platform(os_):
    o = (os_ or "").lower()
    return "Windows" if o.startswith("windows") else "Mac OS" if o.startswith("mac") else "Linux" if "linux" in o or o.startswith("debian") or o.startswith("ubuntu") else ""

@app.get("/api/ab")
def api_ab_get(req: Request):
    """Личная книга пользователя + автоматически все доступные ему компьютеры (метка = группа).
    Добавленные панелью записи запоминаются в ab.auto и убираются, когда доступ пропадает."""
    u = need_user(req)
    with db() as c: r = c.execute("select data, auto from ab where username=?", (u["username"],)).fetchone()
    try: book = json.loads(r["data"]) if r and r["data"] else {}
    except ValueError: book = {}
    if not isinstance(book, dict): book = {}
    peers = [p for p in book.get("peers", []) if isinstance(p, dict)]
    tags = [t for t in book.get("tags", []) if isinstance(t, str)]
    auto_old = set(json.loads(r["auto"] or "[]")) if r else set()
    vis = {pid(d["id"]): d for d in visible_devices(u)}; dg = dev_groups()
    peers = [p for p in peers if not (p.get("id") in auto_old and p.get("id") not in vis)]   # доступ пропал
    have = {p.get("id") for p in peers}; auto = set(i for i in auto_old if i in vis)
    for i, d in vis.items():
        tag = dg.get(d["id"], [])
        if i in have:
            if i in auto:   # обновляем то, что добавила панель
                for p in peers:
                    if p.get("id") == i:
                        p.update(hostname=d["hostname"] or "", username=d["username"] or "", platform=_platform(d["os"]))
                        p["tags"] = list(p.get("tags", [])) + [t for t in tag if t not in p.get("tags", [])]
            continue
        peers.append({"id": i, "hash": "", "username": d["username"] or "", "hostname": d["hostname"] or "",
                      "platform": _platform(d["os"]), "alias": d["hostname"] or "", "tags": tag})
        auto.add(i)
    with db() as c: favs = {pid(r[0]) for r in c.execute("select id from favs where username=?", (u["username"],))}
    for p in peers:   # метка «⭐ Избранное» — по звёздочкам в панели
        t = [x for x in p.get("tags", []) if x != FAV_TAG]
        if p.get("id") in favs: t.append(FAV_TAG)
        p["tags"] = t
    if favs and FAV_TAG not in tags: tags.insert(0, FAV_TAG)
    if not favs and FAV_TAG in tags: tags.remove(FAV_TAG)
    for d in vis.values():
        for g in dg.get(d["id"], []):
            if g not in tags: tags.append(g)
    book.update(peers=peers, tags=tags); book.setdefault("tag_colors", "{}")
    data = json.dumps(book, ensure_ascii=False)
    with db() as c:
        c.execute("insert into ab(username, data, updated_at, auto) values(?,?,?,?) on conflict(username) do update set data=excluded.data, auto=excluded.auto",
                  (u["username"], data, now(), json.dumps(sorted(auto))))
    return {"data": data}

def _fav_ids(data):
    """ID (без «@сервер?key=…») записей адресной книги с меткой «⭐ Избранное»."""
    try: book = json.loads(data) if data else {}
    except ValueError: return set()
    peers = book.get("peers", []) if isinstance(book, dict) else []
    return {str(p.get("id", "")).split("@")[0] for p in peers
            if isinstance(p, dict) and FAV_TAG in (p.get("tags") or []) and ID_RX.match(str(p.get("id", "")).split("@")[0])}

@app.post("/api/ab")
async def api_ab_set(req: Request):
    """Клиент сохранил адресную книгу. Метка «⭐ Избранное», поставленная или снятая в клиенте, → звёздочка в панели
    (сравниваем с прошлой версией книги, чтобы не затереть звёздочки, поставленные в панели за это время)."""
    u = need_user(req); j = await body_json(req)
    data = str(j.get("data", ""))[:1_000_000]
    with db() as c:
        r = c.execute("select data from ab where username=?", (u["username"],)).fetchone()
        old, new = _fav_ids(r["data"] if r else ""), _fav_ids(data)
        for i in new - old: c.execute("insert or ignore into favs(username, id) values(?,?)", (u["username"], i))
        for i in old - new: c.execute("delete from favs where username=? and id=?", (u["username"], i))
        c.execute("insert into ab(username, data, updated_at) values(?,?,?) on conflict(username) do update set data=excluded.data, updated_at=excluded.updated_at",
                  (u["username"], data, now()))
    if new != old: print(f"[ab] избранное {u['username']} из клиента: +{sorted(new - old)} -{sorted(old - new)}", flush=True)
    return {}

@app.post("/api/ab/get")
def api_ab_get_post(req: Request): return api_ab_get(req)

# ---------------------------------------------------------------- админка: пользователи и группы
def user_row(r, counts=None, groups=None):
    g = (groups or {}).get(r["username"], [])
    return {"devices": (counts or {}).get(r["username"], 0), "username": r["username"], "display_name": r["display_name"], "is_admin": bool(r["is_admin"]),
            "groups": g, "group": ", ".join(g), "source": r["source"] or "local", "note": r["note"] or "", "created_at": r["created_at"], "last_login": r["last_login"],
            "can_connect": bool(r["can_connect"]), "can_password": bool(r["can_password"]), "totp": bool(r["totp_on"]),
            "role": "admin" if r["is_admin"] and not r["role"] else (r["role"] or ""), "ad_roles": _jl(r["ad_roles"]), "ad_manual": bool(r["ad_manual"])}

@app.get("/admin/api/users")
def admin_users(req: Request):
    admin_only(req)
    with db() as c:
        counts = {r[0]: r[1] for r in c.execute("select owner, count(*) from devices where owner<>'' group by owner")}
        groups = {}
        for un, g in c.execute("select username, group_name from user_groups order by group_name"): groups.setdefault(un, []).append(g)
        return {"users": [user_row(r, counts, groups) for r in c.execute("select * from users order by is_admin desc, username")]}

@app.post("/admin/api/users/{name}/groups")
async def admin_user_groups(name: str, req: Request):
    """Полный список групп пользователя (новые названия создаются)."""
    admin_only(req); csrf(req); stepup(req, "группы пользователя"); j = await body_json(req)
    if not get_user(name): raise HTTPException(404)
    gs = clean_groups(j.get("groups"))
    with db() as c: set_user_groups(c, name, gs)
    return {"ok": True, "groups": gs}

@app.post("/admin/api/users/{name}/devices")
async def admin_user_devices(name: str, req: Request):
    """Назначить пользователю компьютеры: ids — полный список его компьютеров."""
    admin_only(req); csrf(req); stepup(req, "компьютеры пользователя"); j = await body_json(req)
    if not get_user(name): raise HTTPException(404)
    ids = [str(i) for i in (j.get("ids") or []) if ID_RX.match(str(i))][:2000]
    with db() as c:
        c.execute("update devices set owner='' where owner=?", (name,))
        for i in ids:
            if c.execute("select 1 from devices where id=?", (i,)).fetchone():
                c.execute("update devices set owner=? where id=?", (name, i))
    return {"ok": True, "count": len(ids)}

@app.post("/admin/api/users")
async def admin_user_save(req: Request):
    admin_only(req); csrf(req); stepup(req, "пользователь: создание/изменение"); j = await body_json(req)
    name = str(j.get("username", "")).strip()
    if not USER_RX.match(name): raise HTTPException(400, "Логин: 2–40 символов, латиница, цифры, . _ @ -")
    pw = str(j.get("password") or "")
    if pw and len(pw) < 8: raise HTTPException(400, "Пароль — минимум 8 символов")
    is_admin = 1 if j.get("is_admin") else 0
    groups = clean_groups(j["groups"] if "groups" in j else j.get("group")); disp = clip(j.get("display_name"), 80).strip(); note = clip(j.get("note"), 300)
    me = session_user(req)
    with db() as c:
        ex = c.execute("select * from users where username=?", (name,)).fetchone()
        if not ex:
            if not pw: raise HTTPException(400, "Для нового пользователя нужен пароль")
            c.execute("insert into users(username, display_name, pw_hash, is_admin, group_name, note, created_at) values(?,?,?,?,'',?,?)",
                      (name, disp, pw_hash(pw), is_admin, note, now()))
            set_user_groups(c, name, groups)
        else:
            if ex["is_admin"] and not is_admin and name == me["username"]: raise HTTPException(400, "Нельзя снять права администратора с себя")
            if (ex["source"] or "local") == "ad" and pw: raise HTTPException(400, "Пароль пользователя из Active Directory меняется в AD")
            c.execute("update users set display_name=?, is_admin=?, note=? where username=?", (disp, is_admin, note, name))
            set_user_groups(c, name, groups)
            if pw:
                c.execute("update users set pw_hash=?, sess_ver=coalesce(sess_ver,0)+1 where username=?", (pw_hash(pw), name))
                c.execute("delete from tokens where username=?", (name,))
    return {"ok": True}

@app.delete("/admin/api/users/{name}")
def admin_user_delete(name: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "пользователь: удаление")
    if name == session_user(req)["username"]: raise HTTPException(400, "Нельзя удалить себя")
    with db() as c:
        c.execute("delete from users where username=?", (name,)); c.execute("delete from tokens where username=?", (name,))
        c.execute("update devices set owner='' where owner=?", (name,))
        c.execute("delete from ab where username=?", (name,)); c.execute("delete from user_groups where username=?", (name,))
        c.execute("delete from favs where username=?", (name,))
    return {"ok": True}

@app.post("/admin/api/devices/{i}/group")
async def device_group(i: str, req: Request):
    admin_only(req); csrf(req); j = await body_json(req)
    groups = j.get("groups") if isinstance(j.get("groups"), list) else ([j.get("group")] if j.get("group") else [])
    return {"ok": True, "groups": set_dev_groups(i, [clip(g, 60) for g in groups][:50])}

@app.post("/admin/api/devices/{i}/person")
async def device_person(i: str, req: Request):
    """Имя и фамилия пользователя ПК (вписывает админ; для ПК в домене имя берётся из AD)."""
    admin_only(req); csrf(req); j = await body_json(req)
    upsert(i, person=" ".join(clip(j.get("person"), 120).split())); return {"ok": True}

def ensure_group(g):
    if g:
        with db() as c: c.execute("insert or ignore into groups(name, created_at) values(?,?)", (g, now()))

GROUP_RX = re.compile(r"^[^\x00-\x1f<>]{1,60}$")

@app.get("/admin/api/groups")
def admin_groups(req: Request):
    admin_only(req)
    with db() as c:
        uc = {r[0]: r[1] for r in c.execute("select group_name, count(*) from user_groups group by group_name")}
        dc = {r[0]: r[1] for r in c.execute("select group_name, count(*) from device_groups group by group_name")}
        items = [{"name": r["name"], "note": r["note"] or "", "users": uc.get(r["name"], 0), "devices": dc.get(r["name"], 0), "created_at": r["created_at"],
                  "can_connect": bool(r["can_connect"]), "can_password": bool(r["can_password"]), "role": r["role"] or ""}
                 for r in c.execute("select * from groups order by name")]
    return {"groups": [i["name"] for i in items], "items": items}

@app.post("/admin/api/groups")
async def admin_group_save(req: Request):
    """Создать (name), изменить заметку или переименовать (old_name → name)."""
    admin_only(req); csrf(req); j = await body_json(req)
    name = str(j.get("name", "")).strip(); old = str(j.get("old_name", "")).strip(); note = clip(j.get("note"), 300)
    if not GROUP_RX.match(name): raise HTTPException(400, "Название группы: 1–60 символов")
    with db() as c:
        if old and old != name:
            if not c.execute("select 1 from groups where name=?", (old,)).fetchone(): raise HTTPException(404, "Группа не найдена")
            if c.execute("select 1 from groups where name=?", (name,)).fetchone(): raise HTTPException(400, "Группа с таким названием уже есть")
            c.execute("update groups set name=?, note=? where name=?", (name, note, old))
            c.execute("update user_groups set group_name=? where group_name=?", (name, old))
            c.execute("update device_groups set group_name=? where group_name=?", (name, old))
            c.execute("update devices set group_name=? where group_name=?", (name, old))
        elif c.execute("select 1 from groups where name=?", (name,)).fetchone():
            c.execute("update groups set note=? where name=?", (note, name))
        else:
            c.execute("insert into groups(name, note, created_at) values(?,?,?)", (name, note, now()))
    return {"ok": True}

@app.delete("/admin/api/groups/{name}")
def admin_group_delete(name: str, req: Request):
    admin_only(req); csrf(req)
    with db() as c:
        c.execute("delete from groups where name=?", (name,))
        c.execute("delete from user_groups where group_name=?", (name,))
        c.execute("delete from device_groups where group_name=?", (name,)); sync_primary_group(c)
    return {"ok": True}

@app.post("/admin/api/groups/{name}/members")
async def admin_group_members(name: str, req: Request):
    """Полный состав группы: users — логины, devices — ID. Кто был в группе и не попал в списки — выходит из неё."""
    admin_only(req); csrf(req); stepup(req, "состав группы"); j = await body_json(req)
    users = [str(u) for u in (j.get("users") or [])][:2000]; devs = [str(d) for d in (j.get("devices") or []) if ID_RX.match(str(d))][:5000]
    with db() as c:
        if not c.execute("select 1 from groups where name=?", (name,)).fetchone(): raise HTTPException(404, "Группа не найдена")
        c.execute("delete from user_groups where group_name=?", (name,))   # у пользователя остаются другие группы
        # компьютер, как и пользователь, остаётся в своих других группах
        was = [r[0] for r in c.execute("select id from device_groups where group_name=?", (name,))]
        c.execute("delete from device_groups where group_name=?", (name,))
        nu = sum(c.execute("insert or ignore into user_groups(username, group_name) select username, cast(? as text) from users where username=?", (name, u)).rowcount for u in users)
        nd = sum(c.execute("insert into device_groups(id, group_name) select id, cast(? as text) from devices where id=? on conflict do nothing", (name, d)).rowcount for d in devs)
        sync_primary_group(c, set(was) | set(devs))
    return {"ok": True, "users": nu, "devices": nd}

@app.get("/admin/api/ad")
def admin_ad_get(req: Request):
    admin_only(req); cfg = ad_cfg()
    cfg["bind_pw"] = "••••••••" if cfg["bind_pw"] else ""
    with db() as c: cfg["users"] = c.execute("select count(*) from users where source='ad'").fetchone()[0]
    return cfg

@app.post("/admin/api/ad")
async def admin_ad_save(req: Request):
    admin_only(req); csrf(req); stepup(req, "настройки AD"); j = await body_json(req)
    with db() as c:
        for k in AD_KEYS:
            if k not in j: continue
            v = "1" if (k == "enabled" and j[k] in (True, "1", 1)) else ("0" if k == "enabled" else clip(j[k], 300))
            if k == "kind" and v not in KIND_NAME: v = "ad"
            if k == "bind_pw" and v == "••••••••": continue      # маска — пароль не меняли
            c.execute("insert into settings(k, v) values(?,?) on conflict(k) do update set v=excluded.v", ("ad_" + k, v))
    return {"ok": True}

@app.post("/admin/api/ad/test")
async def admin_ad_test(req: Request):
    """Проверка: подключение сервисной учёткой; если указан login — что панель знает о нём (группы, права);
    если ещё и password — проверка пароля. Ничего не сохраняет."""
    admin_only(req); csrf(req); j = await body_json(req)
    cfg = ad_cfg()
    for k in AD_KEYS:
        if k in j and k != "enabled" and not (k == "bind_pw" and j[k] == "••••••••"): cfg[k] = clip(j[k], 300)
    out = {"steps": []}
    try:
        svc = _ad_service(cfg); svc.unbind(); out["steps"].append("✓ подключение и вход сервисной учётки")
    except Exception as e:
        out["steps"].append("✗ " + (str(e) or type(e).__name__)[:300]); return out
    login = str(j.get("login") or "").strip()
    if login:
        try: f = ad_lookup(cfg, login)
        except Exception as e: out["steps"].append("✗ поиск: " + str(e)[:200]); return out
        if not f: out["steps"].append(f"✗ пользователь «{login}» не найден в {cfg['base_dn']}"); return out
        dn, sam, disp, groups, disabled = f
        adm, mapped = ad_map(cfg, groups)
        out["steps"].append(f"✓ найден: {sam} ({disp}){' — ОТКЛЮЧЁН' if disabled else ''}")
        out["steps"].append("группы AD: " + (", ".join(groups) or "нет"))
        out["steps"].append("в панели: " + ("администратор; " if adm else "") + ("группы " + ", ".join(mapped) if mapped else "без групп") +
                            ("" if adm or mapped else " — ВХОД БУДЕТ ЗАПРЕЩЁН (нет групп с префиксом «" + cfg["group_prefix"] + "»)"))
        if j.get("password"):
            from ldap3 import Connection
            uc = Connection(_ad_server(cfg), user=dn, password=str(j["password"]), receive_timeout=8, raise_exceptions=False)
            ok = uc.bind(); uc.unbind()
            out["steps"].append("✓ пароль верный" if ok else "✗ пароль неверный")
    return out

_ADST = {"at": 0, "ok": None, "err": ""}
def ad_domain(cfg):
    return ".".join(x.split("=", 1)[1] for x in cfg["base_dn"].split(",") if x.strip().upper().startswith("DC=")) if cfg["base_dn"] else ""

@app.get("/admin/api/ad/status")
def admin_ad_status(req: Request, fresh: int = 0):
    """Для кнопки в шапке: в домене ли панель, какой домен, отвечает ли контроллер (проверка не чаще раза в минуту)."""
    admin_only(req); cfg = ad_cfg()
    joined = cfg["enabled"] == "1" and bool(cfg["url"])
    if joined and (fresh or time.time() - _ADST["at"] > 60):
        _ADST["at"] = time.time()
        try: _ad_service(cfg).unbind(); _ADST.update(ok=True, err="")
        except Exception as e: _ADST.update(ok=False, err=(str(e) or type(e).__name__)[:200])
    with db() as c: n = c.execute("select count(*) from users where source='ad'").fetchone()[0]
    return {"joined": joined, "kind": cfg.get("kind") or "ad", "kind_name": KIND_NAME.get(cfg.get("kind") or "ad", "AD"), "domain": ad_domain(cfg).upper(), "url": cfg["url"], "bind_user": cfg["bind_user"],
            "admin_group": cfg["admin_group"], "group_prefix": cfg["group_prefix"], "ok": _ADST["ok"] if joined else None,
            "error": _ADST["err"] if joined else "", "users": n}

@app.post("/admin/api/ad/join")
async def admin_ad_join(req: Request):
    """«Ввести в AD»: домен + (необязательно) контроллер + учётка. Base DN из имени домена, контроллер — по DNS домена,
    проверка входа; по желанию создать в AD группу администраторов RDS. Сохраняет и включает вход через AD."""
    admin_only(req); csrf(req); stepup(req, "ввод в домен"); j = await body_json(req)
    from ldap3 import Connection
    from ldap3.utils.conv import escape_filter_chars as esc
    dom = str(j.get("domain") or "").strip().lower().strip(".")
    if not re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", dom): raise HTTPException(400, "Домен в формате corp.example.local")
    user = str(j.get("user") or "").strip(); pw = str(j.get("password") or "")
    if not user or not pw: raise HTTPException(400, "Нужны учётка и пароль домена (FreeIPA анонимно не показывает группы пользователей)")
    kind = "freeipa" if str(j.get("kind") or "") == "freeipa" else "ad"
    base = ",".join(("dc=" if kind == "freeipa" else "DC=") + x for x in dom.split("."))
    if kind == "ad" and "@" not in user and "\\" not in user: user = f"{user}@{dom}"
    srv = str(j.get("server") or "").strip()
    if srv:
        url = srv if "://" in srv else f"ldap://{srv}" + ("" if ":" in srv else ":389")
    else:
        try: socket.gethostbyname(dom)
        except OSError: raise HTTPException(400, f"Имя {dom} не находится в DNS этого сервера — укажите адрес контроллера домена")
        url = f"ldap://{dom}:389"
    dflt = {"ad": ("RDS Admins", "RDS "), "freeipa": ("rds-admins", "rds-")}[kind]
    cfg = {**ad_cfg(), "kind": kind, "url": url, "base_dn": base, "bind_user": user, "bind_pw": pw, "upn_suffix": dom,
           "admin_group": str(j.get("admin_group") or dflt[0]).strip(), "group_prefix": str(j.get("group_prefix") or dflt[1])}
    steps = []
    try:
        c = _ad_service(cfg); steps.append(f"✓ сервер {url} ответил, " + (f"учётка {bind_dn(cfg)} вошла" if user else "анонимный вход разрешён"))
    except Exception as e:
        raise HTTPException(400, "Не удалось войти в домен: " + (str(e) or type(e).__name__)[:250])
    try:
        from ldap3 import BASE
        if not c.search(base, "(objectClass=*)", search_scope=BASE, attributes=["objectClass"]) or not c.entries:
            raise HTTPException(400, f"В каталоге нет {base} — проверьте имя домена")
        g = cfg["admin_group"]
        c.search(base, f"(&(|(objectClass=group)(objectClass=groupOfNames))(cn={esc(g)}))", attributes=["cn"], size_limit=1)
        if c.entries: steps.append(f"✓ группа «{g}» есть в каталоге")
        elif kind == "freeipa": steps.append(f"! группы «{g}» нет — создайте на сервере FreeIPA: ipa group-add {g}  и добавьте администраторов: ipa group-add-member {g} --users=ЛОГИН")
        elif j.get("create_groups"):
            dn = f"CN={g},CN=Users,{base}"
            ok = c.add(dn, ["top", "group"], {"cn": g, "sAMAccountName": g.replace(" ", "")[:20], "groupType": -2147483646,
                                               "description": "Администраторы панели RDS (RustDesk)"})
            steps.append(f"✓ создана группа «{g}» (CN=Users)" if ok else f"✗ группу «{g}» создать не удалось: {c.result.get('description')} — создайте вручную")
        else: steps.append(f"! группы «{g}» в AD нет — создайте её и добавьте администраторов")
    finally:
        c.unbind()
    with db() as cc:
        for k in ("kind", "url", "base_dn", "bind_user", "bind_pw", "upn_suffix", "admin_group", "group_prefix"):
            cc.execute("insert into settings(k, v) values(?,?) on conflict(k) do update set v=excluded.v", ("ad_" + k, cfg[k]))
        cc.execute("insert into settings(k, v) values('ad_enabled','1') on conflict(k) do update set v='1'")
    _ADST.update(at=0)
    steps.append(f"✓ панель введена в домен {dom.upper()} ({KIND_NAME[kind]}): вход учётками домена включён")
    return {"ok": True, "steps": steps}

@app.post("/admin/api/ad/leave")
def admin_ad_leave(req: Request):
    """Вывести из домена: вход через AD выключается, настройки остаются (можно включить снова). AD-пользователи панели не удаляются."""
    admin_only(req); csrf(req); stepup(req, "вывод из домена")
    with db() as c: c.execute("insert into settings(k, v) values('ad_enabled','0') on conflict(k) do update set v='0'")
    return {"ok": True}

@app.get("/admin/api/me")
def admin_me(req: Request):
    u = panel_user(req); p = perms(u)
    srv = {"rds": RDS_HOST, "key": server_key()} if p["connect"] else {"rds": "", "key": ""}
    pc = power_cfg()
    return {"username": u["username"], "display_name": u["display_name"] or u["username"], "is_admin": bool(u["is_admin"]), "perms": p, "srv": srv,
            "power": {"shutdown_delay": pc["shutdown_delay"], "reboot_delay": pc["reboot_delay"]}}

@app.get("/admin/api/settings")
def admin_settings_get(req: Request):
    admin_only(req); return _settings_out()

def _settings_out():
    pc = power_cfg()
    return {"direct_connect": setting("direct_connect", "1") == "1", "pwr_shutdown_delay": pc["shutdown_delay"],
            "pwr_reboot_delay": pc["reboot_delay"], "pwr_message": pc["message"], "pwr_default_message": PWR_DEF_MSG,
            "agent_key_strict": agent_strict(), "agents_unbound": _agents_unbound(),
            "admin_2fa_required": setting("admin_2fa_required", "0") == "1", "ad_approval": setting("ad_approval", "0") == "1",
            "isp_lookup": isp_on(), "isp_db": ISP["file"], "isp_err": ISP["err"], "isp_busy": ISP["busy"], **backup_cfg()}

# ---------------------------------------------------------------- резервные копии базы (делает служба rds-pg-backup на хосте, настройки — здесь)
BACKUP_DIR = Path("/data/backup")
BACKUP_KEYS = {"backup_every_h": (24, 1, 168, "Как часто — от 1 до 168 часов"),
               "backup_keep_days": (14, 1, 3650, "Хранить — от 1 до 3650 дней"),
               "backup_max_mb": (2048, 50, 1000000, "Предел размера — от 50 МБ")}
BACKUP_DIR_DEF = "/opt/RDS/data/backup"
BACKUP_DIR_RX = re.compile(r"^(/mnt/|/media/|/srv/|/home/|/backup(/|$)|/opt/RDS/data/backup(/|$))[A-Za-z0-9._/-]*$")
def backup_dir_ok(d): return bool(BACKUP_DIR_RX.match(d)) and ".." not in d and "//" not in d and d not in ("/mnt/", "/media/", "/srv/", "/home/")
def backup_cfg():
    out = {"backup_dir": setting("backup_dir", "") or BACKUP_DIR_DEF}
    for k, (d, lo, hi, _) in BACKUP_KEYS.items():
        try: out[k] = max(lo, min(hi, int(setting(k, str(d)))))
        except ValueError: out[k] = d
    return out

# ---------------------------------------------------------------- внешние хранилища копий (rds-vault) и шифрование копий (age)
# Как ноды Remnawave: панель — CA; хранилищу выпускается сертификат (VAULT_SECRET), серверу RDS — клиентский.
# Копии шифрует служба на хосте открытым ключом age (закрытый ключ отдаётся администратору один раз, на сервере не хранится).
VAULT_CA_DIR = D / "vault-ca"; VAULT_HOST_DIR = BACKUP_DIR / ".vault"
with db() as c:
    c.execute("create table if not exists vaults(id bigserial primary key, name text, host text, port int, created_at bigint)")

def _bech32(hrp, data8):
    CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    acc = bits = 0; d5 = []
    for b in data8:
        acc = (acc << 8) | b; bits += 8
        while bits >= 5: bits -= 5; d5.append((acc >> bits) & 31)
    if bits: d5.append((acc << (5 - bits)) & 31)
    def polymod(v):
        g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; chk = 1
        for x in v:
            t = chk >> 25; chk = (chk & 0x1ffffff) << 5 ^ x
            for i in range(5): chk ^= g[i] if (t >> i) & 1 else 0
        return chk
    hx = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = polymod(hx + d5 + [0] * 6) ^ 1
    return hrp + "1" + "".join(CH[x] for x in d5 + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

def age_keypair():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as S
    k = X25519PrivateKey.generate()
    sk = k.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption()); pk = k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
    return _bech32("age-secret-key-", sk).upper(), _bech32("age", pk)

def _vault_ca():
    """CA панели для хранилищ (создаётся при первом обращении) → (ключ, сертификат)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization as S
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as dt
    VAULT_CA_DIR.mkdir(parents=True, exist_ok=True); os.chmod(VAULT_CA_DIR, 0o700)
    kf, cf = VAULT_CA_DIR / "ca.key", VAULT_CA_DIR / "ca.crt"
    if kf.exists() and cf.exists():
        return S.load_pem_private_key(kf.read_bytes(), None), x509.load_pem_x509_certificate(cf.read_bytes())
    key = ec.generate_private_key(ec.SECP256R1()); nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"RDS vault CA ({ADMIN_HOST})")])
    t = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(t - dt.timedelta(days=1)).not_valid_after(t + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False).sign(key, hashes.SHA256()))
    kf.write_bytes(key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption())); os.chmod(kf, 0o600)
    cf.write_bytes(cert.public_bytes(S.Encoding.PEM))
    return key, cert

def _vault_cert(cn, san=None, client=False):
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization as S
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as dt, ipaddress
    cak, cac = _vault_ca(); key = ec.generate_private_key(ec.SECP256R1()); t = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).issuer_name(cac.subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(t - dt.timedelta(days=1)).not_valid_after(t + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=True,
                                      key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cak.public_key()), False))
    if san:
        try: b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san))]), False)
        except ValueError: b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
    cert = b.sign(cak, hashes.SHA256())
    return (cert.public_bytes(S.Encoding.PEM).decode(), key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()).decode(),
            cac.public_bytes(S.Encoding.PEM).decode())

def _vault_host_sync():
    """Конфиг для службы на хосте: список хранилищ + клиентский сертификат сервера RDS."""
    VAULT_HOST_DIR.mkdir(parents=True, exist_ok=True); os.chmod(VAULT_HOST_DIR, 0o700)
    if not (VAULT_HOST_DIR / "client.crt").exists():
        crt, key, ca = _vault_cert(f"rds-uploader ({ADMIN_HOST})", client=True)
        (VAULT_HOST_DIR / "client.key").write_text(key); os.chmod(VAULT_HOST_DIR / "client.key", 0o600)
        (VAULT_HOST_DIR / "client.crt").write_text(crt); (VAULT_HOST_DIR / "ca.crt").write_text(ca)
    with db() as c: vs = [{"id": r["id"], "name": r["name"], "url": f"https://{r['host']}:{r['port']}"} for r in c.execute("select * from vaults order by id")]
    tmp = VAULT_HOST_DIR / ".vaults.tmp"; tmp.write_text(json.dumps(vs, ensure_ascii=False)); os.replace(tmp, VAULT_HOST_DIR / "vaults.json")

VHOST_RX = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
@app.get("/admin/api/vaults")
def admin_vaults(req: Request):
    admin_only(req)
    try: st = json.loads((VAULT_HOST_DIR / "status.json").read_text())
    except (OSError, ValueError): st = {}
    with db() as c: vs = [{**dict(r), "status": st.get(str(r["id"]))} for r in c.execute("select * from vaults order by id")]
    rec = setting("backup_age_recipient", "")
    return {"vaults": vs, "age_recipient": rec, "encrypted": bool(rec)}

@app.post("/admin/api/vaults")
async def admin_vault_add(req: Request):
    """Добавить хранилище {name, host, port, dir?}: выпустить ему сертификат, вернуть команду установки (VAULT_SECRET показывается один раз)."""
    admin_only(req); csrf(req); stepup(req, "хранилище копий: добавление"); j = await body_json(req)
    name = clip(j.get("name"), 60).strip() or "хранилище"; host = str(j.get("host") or "").strip()
    try: port = int(j.get("port") or 8743)
    except ValueError: raise HTTPException(400, "Порт — число")
    if not VHOST_RX.match(host) or not 1 <= port <= 65535: raise HTTPException(400, "Адрес — IP или имя, порт 1–65535")
    vdir = str(j.get("dir") or "/opt/rds-vault/data").strip()
    if not re.match(r"^/[A-Za-z0-9._/-]+$", vdir) or ".." in vdir: raise HTTPException(400, "Каталог — абсолютный путь без пробелов")
    crt, key, ca = _vault_cert(f"rds-vault {name}", san=host)
    sec = base64.b64encode(json.dumps({"vaultCertPem": crt, "vaultKeyPem": key, "caCertPem": ca}).encode()).decode()
    with db() as c: c.execute("insert into vaults(name, host, port, created_at) values(?,?,?,?)", (name, host, port, now()))
    _vault_host_sync()
    cmd = f"curl -fsSL {CLIENT_URL}/vault/install.sh | sudo VAULT_SECRET='{sec}' VAULT_PORT={port} VAULT_DIR={vdir} sh"
    return {"ok": True, "install": cmd, "note": "Выполните команду на машине хранилища. VAULT_SECRET содержит закрытый ключ хранилища и больше не показывается."}

@app.delete("/admin/api/vaults/{vid}")
def admin_vault_delete(vid: int, req: Request):
    """Убрать хранилище из рассылки (копии в нём остаются, его сертификат больше не нужен)."""
    admin_only(req); csrf(req); stepup(req, "хранилище копий: удаление")
    with db() as c:
        if not c.execute("delete from vaults where id=?", (vid,)).rowcount: raise HTTPException(404)
    _vault_host_sync(); return {"ok": True}

@app.post("/admin/api/backup-key")
def admin_backup_key(req: Request):
    """Новый ключ шифрования копий: открытый — на сервер (им шифрует служба), закрытый — администратору, ОДИН раз."""
    admin_only(req); csrf(req); stepup(req, "ключ шифрования копий")
    sk, pk = age_keypair()
    with db() as c: c.execute("insert into settings(k, v) values('backup_age_recipient', ?) on conflict(k) do update set v=excluded.v", (pk,))
    BACKUP_DIR.mkdir(parents=True, exist_ok=True); tmp = BACKUP_DIR / ".age-recipient.tmp"; tmp.write_text(pk + "\n"); os.replace(tmp, BACKUP_DIR / ".age-recipient")
    return {"ok": True, "recipient": pk, "secret": sk}

VAULT_SRC = Path(__file__).parent / "vault"
@app.get("/vault/{name}")
def vault_files(name: str, req: Request):
    """Установщик и код хранилища (без секретов) — для команды из панели."""
    client_only(req)
    if name not in ("install.sh", "vault.py"): raise HTTPException(404)
    t = (VAULT_SRC / name).read_text(encoding="utf-8").replace("__BASE__", CLIENT_URL)
    return PlainTextResponse(t, headers={"Cache-Control": "no-store"})

@app.get("/admin/api/backups")
def admin_backups(req: Request):
    admin_only(req)
    try: idx = json.loads((BACKUP_DIR / ".index.json").read_text())   # список пишет служба на хосте (каталог может быть вне контейнера)
    except (OSError, ValueError): idx = {"files": [{"name": f.name, "size": f.stat().st_size, "ts": int(f.stat().st_mtime)} for f in BACKUP_DIR.glob("rds-*.sql.gz")]}
    files = sorted(idx.get("files") or [], key=lambda x: -int(x.get("ts") or 0))
    try: st = json.loads((BACKUP_DIR / ".status").read_text())
    except (OSError, ValueError): st = None
    return {"files": files[:50], "count": len(files), "total": sum(int(f.get("size") or 0) for f in files), "status": st,
            "real_dir": idx.get("dir") or "", "warn": idx.get("warn") or "", "free": idx.get("free"),
            "pending": (BACKUP_DIR / ".request").exists(), **backup_cfg()}

@app.post("/admin/api/backups/now")
def admin_backup_now(req: Request):
    """Копия вне расписания: служба на хосте проверяет запрос каждые 15 минут."""
    admin_only(req); csrf(req)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True); (BACKUP_DIR / ".request").write_text(str(now()))
    admin_log(session_user(req)["username"], _ip(req), "резервная копия: запрос вне расписания")
    return {"ok": True}

def _agents_unbound():
    with db() as c: return c.execute("select count(*) from devices where coalesce(agent_key_sha,'')=''").fetchone()[0]

@app.post("/admin/api/settings")
async def admin_settings_set(req: Request):
    admin_only(req); csrf(req); stepup(req, "настройки панели"); j = await body_json(req)
    if "direct_connect" in j:
        with db() as c: c.execute("insert into settings(k, v) values('direct_connect', ?) on conflict(k) do update set v=excluded.v",
                                  ("1" if j.get("direct_connect") else "0",))
    if "admin_2fa_required" in j:
        me = session_user(req)
        if j.get("admin_2fa_required") and not me["totp_on"]: raise HTTPException(400, "Сначала включите 2FA себе, иначе вы потеряете доступ к настройкам")
        with db() as c: c.execute("insert into settings(k, v) values('admin_2fa_required', ?) on conflict(k) do update set v=excluded.v",
                                  ("1" if j.get("admin_2fa_required") else "0",))
    if "ad_approval" in j:
        with db() as c: c.execute("insert into settings(k, v) values('ad_approval', ?) on conflict(k) do update set v=excluded.v",
                                  ("1" if j.get("ad_approval") else "0",))
    if "isp_lookup" in j:
        with db() as c: c.execute("insert into settings(k, v) values('isp_lookup', ?) on conflict(k) do update set v=excluded.v",
                                  ("1" if j.get("isp_lookup") else "0",))
        if j.get("isp_lookup"): threading.Thread(target=isp_refresh, daemon=True).start()
    if "agent_key_strict" in j:
        with db() as c: c.execute("insert into settings(k, v) values('agent_key_strict', ?) on conflict(k) do update set v=excluded.v",
                                  ("1" if j.get("agent_key_strict") else "0",))
    upd = {}
    if "backup_dir" in j:
        bd = str(j.get("backup_dir") or "").strip().rstrip("/") or BACKUP_DIR_DEF
        if not backup_dir_ok(bd): raise HTTPException(400, "Каталог — только внутри /mnt, /media, /srv, /backup, /home или /opt/RDS/data/backup (латиница, цифры, . _ -, без пробелов)")
        upd["backup_dir"] = "" if bd == BACKUP_DIR_DEF else bd
    for k, (_, lo, hi, msg) in BACKUP_KEYS.items():
        if k in j:
            try: v = int(j.get(k))
            except (TypeError, ValueError): raise HTTPException(400, msg)
            if not lo <= v <= hi: raise HTTPException(400, msg)
            upd[k] = str(v)
    for k in ("pwr_shutdown_delay", "pwr_reboot_delay"):
        if k in j:
            try: v = int(j.get(k))
            except (TypeError, ValueError): raise HTTPException(400, "Задержка — целое число секунд")
            if not 0 <= v <= 86400: raise HTTPException(400, "Задержка: от 0 до 86400 секунд (24 ч)")
            upd[k] = str(v)
    if "pwr_message" in j:
        msg = str(j.get("pwr_message") or "").replace("\r", "").strip()
        if len(msg) > 500: raise HTTPException(400, "Сообщение длиннее 500 символов (предел Windows)")
        upd["pwr_message"] = "" if msg == PWR_DEF_MSG else msg
    if upd:
        with db() as c:
            for k, v in upd.items(): c.execute("insert into settings(k, v) values(?, ?) on conflict(k) do update set v=excluded.v", (k, v))
    return _settings_out()

def _perm_flags(j):
    return int(bool(j.get("can_connect"))), int(bool(j.get("can_password")))

@app.get("/admin/api/roles")
def admin_roles(req: Request):
    admin_only(req)
    with db() as c:
        uc = {}
        for r in c.execute("select role from users where coalesce(role,'')<>''"): uc[r[0]] = uc.get(r[0], 0) + 1
        gc = {}
        for r in c.execute("select role from groups where coalesce(role,'')<>''"): gc[r[0]] = gc.get(r[0], 0) + 1
        mc = {}
        for r in c.execute("select role from ad_maps where coalesce(role,'')<>''"): mc[r[0]] = mc.get(r[0], 0) + 1
    return {"roles": [{**r, "users": uc.get(n, 0), "groups": gc.get(n, 0), "ad_maps": mc.get(n, 0)} for n, r in roles_all().items()],
            "perm_keys": PERM_KEYS}

ROLE_RX = re.compile(r"^[a-z0-9_-]{2,30}$")
@app.post("/admin/api/roles")
async def admin_role_save(req: Request):
    """Создать или изменить шаблон: {name?, title, perms:[...]}. «Администратор» не меняется."""
    admin_only(req); csrf(req); stepup(req, "шаблон прав: изменение"); j = await body_json(req)
    title = clip(j.get("title"), 60).strip(); ps = sorted({str(x) for x in (j.get("perms") or []) if str(x) in PERM_KEYS})
    if not title: raise HTTPException(400, "Нужно название шаблона")
    name = str(j.get("name") or "").strip()
    with db() as c:
        if name:
            r = c.execute("select * from roles where name=?", (name,)).fetchone()
            if not r: raise HTTPException(404)
            if name == "admin": raise HTTPException(400, "Шаблон «Администратор» не меняется: в нём все права")
            c.execute("update roles set title=?, perms=? where name=?", (title, json.dumps(ps), name))
        else:
            base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:20] or "role"
            name = "r-" + secrets_token(4).lower().replace("_", "x") if not ROLE_RX.match(base) or c.execute("select 1 from roles where name=?", (base,)).fetchone() else base
            c.execute("insert into roles(name, title, perms, builtin, created_at) values(?,?,?,0,?)", (name, title, json.dumps(ps), now()))
    return {"ok": True, "name": name}

@app.delete("/admin/api/roles/{name}")
def admin_role_delete(name: str, req: Request):
    """Удалить свой шаблон; у пользователей, групп и сопоставлений AD он снимается."""
    admin_only(req); csrf(req); stepup(req, "шаблон прав: удаление")
    with db() as c:
        r = c.execute("select builtin from roles where name=?", (name,)).fetchone()
        if not r: raise HTTPException(404)
        if r["builtin"]: raise HTTPException(400, "Встроенный шаблон можно изменить, но не удалить")
        c.execute("delete from roles where name=?", (name,)); c.execute("update users set role='' where role=?", (name,))
        c.execute("update groups set role='' where role=?", (name,)); c.execute("update ad_maps set role='' where role=?", (name,))
    return {"ok": True}

def _apply_user_role(c, me, name, role):
    ex = c.execute("select * from users where username=?", (name,)).fetchone()
    if not ex: raise HTTPException(404, f"Нет пользователя {name}")
    adm = 1 if role == "admin" else 0
    if ex["is_admin"] and not adm and name == me: raise HTTPException(400, "Нельзя снять права администратора с себя")
    c.execute("update users set role=?, is_admin=? where username=?", ("" if role == "admin" else role, adm, name))
    if ex["is_admin"] != adm: c.execute("update users set sess_ver=coalesce(sess_ver,0)+1 where username=?", (name,))

@app.post("/admin/api/users/role")
async def admin_users_role(req: Request):
    """Назначить шаблон одному или нескольким пользователям: {users:[...], role}. role='' — без шаблона."""
    admin_only(req); csrf(req); stepup(req, "шаблон прав: назначение"); j = await body_json(req)
    role = str(j.get("role") or ""); names = [str(x) for x in (j.get("users") or [])][:500]
    if role and role not in roles_all(): raise HTTPException(400, "Нет такого шаблона")
    me = session_user(req)["username"]
    with db() as c:
        for n in names: _apply_user_role(c, me, n, role)
    return {"ok": True, "n": len(names)}

@app.post("/admin/api/groups/{name}/role")
async def admin_group_role(name: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "шаблон прав группы"); j = await body_json(req)
    role = str(j.get("role") or "")
    if role == "admin": raise HTTPException(400, "Шаблон «Администратор» группе не назначается — только пользователю или группе AD")
    if role and role not in roles_all(): raise HTTPException(400, "Нет такого шаблона")
    with db() as c:
        if not c.execute("update groups set role=? where name=?", (role, name)).rowcount: raise HTTPException(404)
    return {"ok": True}

# ---------------------------------------------------------------- AD: сопоставление групп и вход по одобрению
@app.get("/admin/api/ad/maps")
def admin_ad_maps(req: Request):
    admin_only(req)
    with db() as c:
        maps = [{"id": r["id"], "ad_group": r["ad_group"], "panel_groups": _jl(r["panel_groups"]), "role": r["role"] or ""} for r in c.execute("select * from ad_maps order by ad_group")]
        pend = [{**dict(r), "ad_groups": _jl(r["ad_groups"])} for r in c.execute("select * from ad_pending order by ts desc")]
    return {"maps": maps, "pending": pend, "approval": setting("ad_approval", "0") == "1"}

@app.post("/admin/api/ad/maps")
async def admin_ad_map_save(req: Request):
    """{id?, ad_group, panel_groups:[...], role}: участники группы AD получают эти группы ПК и шаблон."""
    admin_only(req); csrf(req); stepup(req, "сопоставление групп AD"); j = await body_json(req)
    ag = clip(j.get("ad_group"), 200).strip(); pg = clean_groups(j.get("panel_groups") or []); role = str(j.get("role") or "")
    if not ag: raise HTTPException(400, "Нужно имя группы AD")
    if role and role not in roles_all(): raise HTTPException(400, "Нет такого шаблона")
    if not pg and not role: raise HTTPException(400, "Укажите группы ПК и/или шаблон")
    with db() as c:
        if j.get("id"):
            if not c.execute("update ad_maps set ad_group=?, panel_groups=?, role=? where id=?", (ag, json.dumps(pg, ensure_ascii=False), role, int(j["id"]))).rowcount: raise HTTPException(404)
        else:
            c.execute("insert into ad_maps(ad_group, panel_groups, role, created_at) values(?,?,?,?)", (ag, json.dumps(pg, ensure_ascii=False), role, now()))
        for g in pg: c.execute("insert into groups(name, created_at) values(?,?) on conflict do nothing", (g, now()))
    return {"ok": True}

@app.delete("/admin/api/ad/maps/{mid}")
def admin_ad_map_delete(mid: int, req: Request):
    admin_only(req); csrf(req); stepup(req, "сопоставление групп AD: удаление")
    with db() as c:
        if not c.execute("delete from ad_maps where id=?", (mid,)).rowcount: raise HTTPException(404)
    return {"ok": True}

@app.post("/admin/api/ad/pending/{name}")
async def admin_ad_pending(name: str, req: Request):
    """Одобрить {action:'approve', role, groups:[...]} или отклонить {action:'reject'} доменного пользователя из очереди."""
    admin_only(req); csrf(req); stepup(req, "вход по одобрению: решение"); j = await body_json(req)
    with db() as c:
        p_ = c.execute("select * from ad_pending where username=?", (name,)).fetchone()
        if not p_: raise HTTPException(404)
        if j.get("action") == "reject":
            c.execute("delete from ad_pending where username=?", (name,)); return {"ok": True}
        role = str(j.get("role") or ""); groups = clean_groups(j.get("groups") or [])
        if role and role not in roles_all(): raise HTTPException(400, "Нет такого шаблона")
        if not role and not groups: raise HTTPException(400, "Выберите шаблон и/или группы ПК")
        ex = c.execute("select source from users where username=?", (name,)).fetchone()
        if ex and (ex["source"] or "local") != "ad": raise HTTPException(400, "Есть локальный пользователь с таким логином")
        if not ex:
            c.execute("insert into users(username, display_name, pw_hash, is_admin, group_name, note, created_at, source) values(?,?,?,?,'',?,?, 'ad')",
                      (name, p_["display_name"] or name, "", 1 if role == "admin" else 0, "из Active Directory (одобрен)", now()))
        c.execute("update users set ad_manual=1, manual_groups=?, role=?, is_admin=? where username=?",
                  (json.dumps(groups, ensure_ascii=False), "" if role == "admin" else role, 1 if role == "admin" else 0, name))
        set_user_groups(c, name, groups); c.execute("delete from ad_pending where username=?", (name,))
    return {"ok": True}

@app.post("/admin/api/users/{name}/perms")
async def admin_user_perms(name: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "права пользователя"); cc, cp = _perm_flags(await body_json(req))
    with db() as c:
        if not c.execute("select 1 from users where username=?", (name,)).fetchone(): raise HTTPException(404)
        c.execute("update users set can_connect=?, can_password=? where username=?", (cc, cp, name))
    return {"ok": True, "can_connect": bool(cc), "can_password": bool(cp)}

@app.post("/admin/api/groups/{name}/perms")
async def admin_group_perms(name: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "права группы"); cc, cp = _perm_flags(await body_json(req))
    with db() as c:
        if not c.execute("select 1 from groups where name=?", (name,)).fetchone(): raise HTTPException(404)
        c.execute("update groups set can_connect=?, can_password=? where name=?", (cc, cp, name))
    return {"ok": True, "can_connect": bool(cc), "can_password": bool(cp)}



# ---------------------------------------------------------------- программы: каталог и развёртывание
PKG_DIR = D / "pkgs"
SW_KINDS = {"windows": ("msi", "exe", "ps1", "winget"), "linux": ("pkg", "script"), "mac": ("macpkg", "script")}
SW_ACTIONS = ("install", "upgrade", "uninstall")
JOB_TIMEOUT = 2 * 3600

def dev_platform(os_):
    o = (os_ or "").lower()
    return "windows" if "windows" in o else "mac" if o.startswith("mac") or "macos" in o else "linux" if o else ""

def _b64(v): return base64.b64encode(str(v or "").encode("utf-8")).decode()

def _pkg_row(r):
    d = dict(r); d.pop("file", None); return d

def _job_spec(p, action):
    """Снимок того, что агенту надо сделать (правка программы в каталоге не меняет уже поставленные задания)."""
    return {"kind": p["kind"], "action": action, "src": p["source"] or "", "args": p["install_args"] or "",
            "ukind": p["uninstall_kind"] or "", "uargs": p["uninstall_args"] or "", "name": p["detect_name"] or p["name"] or "",
            "cfg": p["config"] or "", "post": p["post_script"] or "", "file": p["file"] or "", "fname": p["file_name"] or "", "sha": p["sha256"] or ""}

def _next_job(c, i):
    """Самое старое задание ПК в очереди → running; для агента всё в base64 (PowerShell 2.0 без JSON-парсера)."""
    c.execute("update sw_jobs set status='error', msg='агент не сообщил результат за 2 ч', finished_at=? where device_id=? and status='running' and started_at<?",
              (now(), i, now() - JOB_TIMEOUT))
    if c.execute("select 1 from sw_jobs where device_id=? and status='running'", (i,)).fetchone(): return None
    j = c.execute("select * from sw_jobs where device_id=? and status='queued' order by id limit 1", (i,)).fetchone()
    if not j: return None
    c.execute("update sw_jobs set status='running', started_at=? where id=?", (now(), j["id"]))
    sp = json.loads(j["spec"] or "{}")
    url = f"{API_URL}/api/rds/pkgfile/{j['id']}/{j['secret']}" if sp.get("file") else (sp.get("src") if re.match(r"^https?://", sp.get("src") or "") else "")
    out = {"id": str(j["id"]), "act": sp.get("action", ""), "kind": sp.get("kind", ""), "sha": sp.get("sha", ""), "fname": sp.get("fname", "")}
    for k in ("src", "args", "ukind", "uargs", "name", "cfg", "post"): out[k + "_b64"] = _b64(sp.get(k))
    out["url_b64"] = _b64(url)
    return out

@app.get("/api/rds/pkgfile/{jid}/{secret}")
def pkg_file(jid: int, secret: str):
    with db() as c: j = c.execute("select status, secret, spec from sw_jobs where id=?", (jid,)).fetchone()
    if not j or j["status"] != "running" or not hmac.compare_digest(str(j["secret"]), secret): raise HTTPException(404)
    sp = json.loads(j["spec"] or "{}"); f = PKG_DIR / str(sp.get("file") or "")
    if not sp.get("file") or not f.is_file(): raise HTTPException(404)
    return FileResponse(f, filename=sp.get("fname") or f.name, media_type="application/octet-stream")

@app.post("/api/rds/jobresult")
async def rds_jobresult(req: Request):
    j = await body_json(req); i = _client_auth(j)
    try: jid = int(j.get("job") or 0)
    except ValueError: raise HTTPException(400)
    ok = bool(j.get("ok")); msg = clip(j.get("msg"), 600)
    code = str(j.get("code") or "").strip()
    if re.fullmatch(r"-?\d+", code) and code != "-1":   # код выхода установщика → по-русски
        c_ = int(code); txt = f"код {c_}" + (": нужна перезагрузка" if c_ in (3010, 1641) else "")
        msg = txt + (" · " + msg if msg else "")
    with db() as c:
        c.execute("update sw_jobs set status=?, msg=?, finished_at=? where id=? and device_id=? and status='running'",
                  ("ok" if ok else "error", msg, now(), jid, i))
    print(f"[sw] {i} задание {jid}: {'ok' if ok else 'ошибка'} {msg[:120]}", flush=True)
    return {"ok": True}

@app.get("/admin/api/pkgs")
def admin_pkgs(req: Request):
    need_perm(req, "deploy")
    with db() as c: return {"pkgs": [_pkg_row(r) for r in c.execute("select * from sw_packages order by name")]}

@app.post("/admin/api/pkgs")
async def admin_pkg_save(req: Request):
    admin_only(req); csrf(req); stepup(req, "каталог ПО: изменение"); j = await body_json(req)
    plat = str(j.get("platform") or ""); kind = str(j.get("kind") or "")
    if plat not in SW_KINDS or kind not in SW_KINDS[plat]: raise HTTPException(400, "Неверная платформа или тип установки")
    name = clip(j.get("name"), 120).strip()
    if not name: raise HTTPException(400, "Нужно название")
    f = {"name": name, "platform": plat, "kind": kind, "source": clip(j.get("source"), 20000), "install_args": clip(j.get("install_args"), 2000),
         "uninstall_kind": clip(j.get("uninstall_kind"), 20), "uninstall_args": clip(j.get("uninstall_args"), 20000),
         "detect_name": clip(j.get("detect_name"), 200), "config": clip(j.get("config"), 20000), "post_script": clip(j.get("post_script"), 20000), "note": clip(j.get("note"), 500), "updated_at": now()}
    with db() as c:
        pid = int(j.get("id") or 0)
        if pid:
            if not c.execute("select 1 from sw_packages where id=?", (pid,)).fetchone(): raise HTTPException(404)
            c.execute("update sw_packages set " + ", ".join(f"{k}=?" for k in f) + " where id=?", (*f.values(), pid))
        else:
            pid = c.execute("insert into sw_packages(" + ", ".join(f) + ", created_at) values(" + ", ".join("?" for _ in f) + ", ?) returning id",
                            (*f.values(), now())).fetchone()[0]
    return {"ok": True, "id": pid}

@app.post("/admin/api/pkgs/{pid}/file")
async def admin_pkg_file(pid: int, req: Request):
    """Файл установщика (MSI/EXE/PKG) — тело запроса как есть, имя в заголовке X-Filename (URL-кодированное)."""
    admin_only(req); csrf(req); stepup(req, "каталог ПО: файл установщика")
    with db() as c: p = c.execute("select file from sw_packages where id=?", (pid,)).fetchone()
    if not p: raise HTTPException(404)
    fname = os.path.basename(urllib.parse.unquote(req.headers.get("x-filename") or "installer.bin"))[:150] or "installer.bin"
    PKG_DIR.mkdir(parents=True, exist_ok=True)
    store = f"{pid}-{secrets_token(8)}{os.path.splitext(fname)[1][:8]}"; tmp = PKG_DIR / (store + ".part")
    h = hashlib.sha256(); size = 0
    with open(tmp, "wb") as out:
        async for chunk in req.stream():
            out.write(chunk); h.update(chunk); size += len(chunk)
            if size > 4 * 1024 ** 3: out.close(); tmp.unlink(missing_ok=True); raise HTTPException(413, "Файл больше 4 ГБ")
    if size == 0: tmp.unlink(missing_ok=True); raise HTTPException(400, "Пустой файл")
    tmp.rename(PKG_DIR / store)
    old = p["file"]
    with db() as c: c.execute("update sw_packages set file=?, file_name=?, file_size=?, sha256=?, updated_at=? where id=?", (store, fname, size, h.hexdigest(), now(), pid))
    if old:
        with db() as c: still = c.execute("select 1 from sw_jobs where status in ('queued','running') and spec like ?", (f'%"{old}"%',)).fetchone()
        if not still: (PKG_DIR / old).unlink(missing_ok=True)
    return {"ok": True, "size": size, "sha256": h.hexdigest(), "file_name": fname}

@app.delete("/admin/api/pkgs/{pid}")
def admin_pkg_delete(pid: int, req: Request):
    admin_only(req); csrf(req); stepup(req, "каталог ПО: удаление")
    with db() as c:
        p = c.execute("select file from sw_packages where id=?", (pid,)).fetchone()
        if not p: raise HTTPException(404)
        c.execute("delete from sw_packages where id=?", (pid,))
        c.execute("update sw_jobs set status='canceled', msg='программа удалена из каталога', finished_at=? where package_id=? and status='queued'", (now(), pid))
    if p["file"]: (PKG_DIR / p["file"]).unlink(missing_ok=True)
    return {"ok": True}

@app.post("/admin/api/jobs")
async def admin_jobs_create(req: Request):
    """Поставить задания: {package_id, action, devices:[ID]} или удаление установленной программы по имени: {action:'uninstall', name, args, devices}."""
    u = need_perm(req, "deploy"); csrf(req); stepup(req, "задание ПО"); j = await body_json(req); me = u["username"]
    action = str(j.get("action") or ""); devs = [str(d) for d in (j.get("devices") or []) if ID_RX.match(str(d))][:2000]
    if action not in SW_ACTIONS or not devs: raise HTTPException(400, "Нужны действие и компьютеры")
    if not u["is_admin"]:
        if not j.get("package_id"): raise HTTPException(403, "Удаление программы по имени — только администратору")
        mine = {d["id"] for d in visible_devices(u)}
        if any(d not in mine for d in devs): raise HTTPException(403, "Часть компьютеров не из ваших групп")
    with db() as c:
        osmap = {r["id"]: dev_platform(r["os"]) for r in c.execute("select id, os from devices")}
        if j.get("package_id"):
            p = c.execute("select * from sw_packages where id=?", (int(j["package_id"]),)).fetchone()
            if not p: raise HTTPException(404, "Программы нет в каталоге")
            if p["kind"] in ("msi", "exe", "macpkg") and action != "uninstall" and not p["file"] and not re.match(r"^https?://", p["source"] or ""):
                raise HTTPException(400, "Для этой программы не загружен установщик и не указана ссылка")
            spec = _job_spec(p, action); plat = p["platform"]; pname = p["name"]; pkg_id = p["id"]
        else:
            name = clip(j.get("name"), 200).strip()
            if action != "uninstall" or not name: raise HTTPException(400, "Удаление по имени: нужно имя программы")
            spec = {"kind": "byname", "action": "uninstall", "name": name, "uargs": clip(j.get("args"), 2000)}; plat = None; pname = name; pkg_id = None
        n = 0; skipped = []
        for d in devs:
            if plat and osmap.get(d) != plat: skipped.append(d); continue
            if spec["kind"] == "byname": spec = {**spec, "plat": osmap.get(d, "")}
            c.execute("insert into sw_jobs(device_id, package_id, pkg_name, action, status, secret, spec, created_by, created_at) values(?,?,?,?,'queued',?,?,?,?)",
                      (d, pkg_id, pname, action, secrets_token(16), json.dumps(spec, ensure_ascii=False), me, now())); n += 1
    print(f"[sw] {me}: {action} «{pname}» на {n} ПК" + (f", пропущено (другая ОС): {skipped}" if skipped else ""), flush=True)
    return {"ok": True, "queued": n, "skipped": skipped}

@app.get("/admin/api/jobs")
def admin_jobs(req: Request, device: str = "", limit: int = 200):
    u = need_perm(req, "deploy"); mine = None if u["is_admin"] else {d["id"] for d in visible_devices(u)}
    with db() as c:
        c.execute("update sw_jobs set status='error', msg='агент не сообщил результат за 2 ч', finished_at=? where status='running' and started_at<?", (now(), now() - JOB_TIMEOUT))
        names = {r["id"]: r["hostname"] for r in c.execute("select id, hostname from devices")}
        q = "select id, device_id, package_id, pkg_name, action, status, msg, created_by, created_at, started_at, finished_at from sw_jobs"
        rows = c.execute(q + (" where device_id=?" if device else "") + " order by id desc limit ?", ((device, min(limit, 1000)) if device else (min(limit, 1000),))).fetchall()
    return {"jobs": [{**dict(r), "hostname": names.get(r["device_id"], "")} for r in rows if mine is None or r["device_id"] in mine]}

@app.post("/admin/api/jobs/{jid}/cancel")
def admin_job_cancel(jid: int, req: Request):
    admin_only(req); csrf(req)
    with db() as c: n = c.execute("update sw_jobs set status='canceled', msg='отменено', finished_at=? where id=? and status='queued'", (now(), jid)).rowcount
    if not n: raise HTTPException(409, "Задание уже выполняется или завершено")
    return {"ok": True}

@app.post("/admin/api/devices/{i}/refresh")
def device_refresh(i: str, req: Request):
    """Кнопка «Обновить данные» в Hardware — то же, что команда iex …/hw.ps1 на самом ПК, но через агента."""
    need_perm(req, "hw", i); csrf(req)
    with db() as c:
        r = c.execute("select cmd, agent_at from devices where id=?", (i,)).fetchone()
        if not r: raise HTTPException(404)
        if r["cmd"] in ("shutdown", "reboot", "update", "running"): raise HTTPException(409, "У ПК уже есть другая команда")
        c.execute("update devices set cmd='hw', cmd_at=? where id=?", (str(now()), i))
    return {"ok": True, "agent_ok": now() - int(r["agent_at"] or 0) < 300}

def secrets_token(n): return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")

# ---------------------------------------------------------------- журнал подключений (клиент шлёт /api/audit/conn и /api/audit/file)
@app.post("/api/audit/{kind}")
async def api_audit(kind: str, req: Request):
    if kind not in ("conn", "file", "alarm"): raise HTTPException(404)
    j = await body_json(req); i = str(j.get("id", ""))
    if not ID_RX.match(i) or not in_hbbs(i): return {}
    peer = j.get("peer") if isinstance(j.get("peer"), list) else []
    act = str(j.get("action", j.get("type", "")))[:40]
    with db() as c:
        c.execute("insert into audit values(?,?,?,?,?,?,?,?)", (now(), kind, i, clip(peer[0] if peer else "", 40), clip(peer[1] if len(peer) > 1 else "", 80),
                  clip(j.get("ip"), 60), act, json.dumps(j, ensure_ascii=False)[:4000]))
        c.execute("delete from audit where ts < ?", (now() - 180 * 86400,))
    return {}

@app.put("/api/audit/{kind}")
async def api_audit_put(kind: str, req: Request): return await api_audit(kind, req)

@app.get("/admin/api/audit")
def admin_audit(req: Request):
    admin_only(req)
    with db() as c:
        rows = [dict(r) for r in c.execute("select ts, kind, id, peer_id, peer_name, ip, action from audit order by ts desc limit 300")]
    return {"events": rows}


# ---------------------------------------------------------------- личный установщик администратора (клиент сразу в аккаунте)
@app.get("/admin/api/installer")
def admin_installer(req: Request, master: int = 1):
    admin_only(req); stepup(req, "личный установщик со входом")
    me = session_user(req)
    tok = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    with db() as c:
        c.execute("insert into tokens values(?,?,?,?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), me["username"], now(), now(),
                  "installer " + time.strftime("%Y-%m-%d %H:%M"), ""))
    w = Path(tempfile.mkdtemp(dir=D))
    try:
        ver = STATE["version"] or current_version() or "1.0"
        vi = ".".join((ver.split(".") + ["0", "0", "0", "0"])[:4])
        ps1 = w / "setup.ps1"; ps1.write_text(render("setup.ps1", bool(master), login_token=tok, login_user=me["username"]), encoding="ascii")
        nsi = w / "setup.nsi"; nsi.write_text(render("setup.nsi", bool(master)), encoding="utf-8-sig")
        out = w / "RustDesk-Setup-admin.exe"
        run(["makensis", "-V2", "-INPUTCHARSET", "UTF8", f"-DOUT={out}", f"-DPS1={ps1}", *NSIS_ART,
             f"-DCAPTION=Установка RustDesk ({me['username']})", f"-DRDVER={ver}", f"-DVIVER={vi}", str(nsi)])
        data = out.read_bytes()
    finally:
        shutil.rmtree(w, ignore_errors=True)
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="RustDesk-Setup-{me["username"]}.exe"', "Cache-Control": "no-store"})

@app.get("/admin/api/tokens")
def admin_tokens(req: Request):
    admin_only(req)
    with db() as c:
        return {"tokens": [dict(r) for r in c.execute("select substr(token_sha,1,12) as ref, username, client_id, created_at, last_used from tokens order by created_at desc")]}

@app.delete("/admin/api/tokens/{ref}")
def admin_token_revoke(ref: str, req: Request):
    admin_only(req); csrf(req); stepup(req, "отзыв токена клиента")
    if not re.match(r"^[0-9a-f]{12}$", ref): raise HTTPException(400)
    with db() as c: c.execute("delete from tokens where substr(token_sha,1,12)=?", (ref,))
    return {"ok": True}


@app.post("/admin/api/devices/{i}/fav")
async def device_fav(i: str, req: Request):
    """Звёздочка: избранное текущего администратора (в его адресной книге RustDesk — метка «⭐ Избранное»)."""
    u = panel_user(req); csrf(req); j = await body_json(req); me = u["username"]
    if not u["is_admin"] and i not in {d["id"] for d in visible_devices(u)}: raise HTTPException(404)
    with db() as c:
        if j.get("fav"): c.execute("insert or ignore into favs values(?,?)", (me, i))
        else: c.execute("delete from favs where username=? and id=?", (me, i))
    return {"ok": True}


@app.post("/admin/api/devices/delete")
async def devices_bulk_delete(req: Request):
    """Удалить выбранные устройства из панели (и старые записи из базы hbbs). RustDesk на самих ПК не трогается."""
    admin_only(req); csrf(req); stepup(req, "удаление ПК (несколько)"); j = await body_json(req)
    ids = [str(i) for i in (j.get("ids") or []) if ID_RX.match(str(i))][:5000]
    n_panel = n_hbbs = 0
    with db() as c:
        for i in ids:
            n_panel += c.execute("delete from devices where id=?", (i,)).rowcount; c.execute("delete from device_groups where id=?", (i,))
            c.execute("delete from favs where id=?", (i,))
    try:
        h = sqlite3.connect(HBBS_DB, timeout=10)
        for i in ids: n_hbbs += h.execute("delete from peer where id=?", (i,)).rowcount
        h.commit(); h.close()
    except sqlite3.Error:
        pass
    return {"ok": True, "panel": n_panel, "hbbs": n_hbbs}
