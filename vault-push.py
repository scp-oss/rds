#!/usr/bin/env python3
"""Отправка зашифрованных копий базы RDS во внешние хранилища rds-vault (запускает pg-backup.sh после копии).

Конфиг пишет панель (☰ → Резервные копии → Хранилища) в /opt/RDS/data/backup/.vault/:
  vaults.json — [{id, name, url}], client.crt/client.key — сертификат сервера RDS, ca.crt — CA панели.
В каждое хранилище уходит самая свежая копия *.age (незашифрованные не отправляются никогда), затем читается список.
Итог по каждому хранилищу — в .vault/status.json (панель его показывает).
"""
import glob, json, os, ssl, sys, time, urllib.request, urllib.error

C = "/opt/RDS/data/backup"; V = os.path.join(C, ".vault")


def main(backup_dir):
    try: vaults = json.load(open(os.path.join(V, "vaults.json")))
    except (OSError, ValueError): return
    if not vaults: return
    try: status = json.load(open(os.path.join(V, "status.json")))
    except (OSError, ValueError): status = {}
    enc = sorted(glob.glob(os.path.join(backup_dir, "rds-*.sql.gz.age")), key=os.path.getmtime)
    newest = enc[-1] if enc else None
    ctx = ssl.create_default_context(cafile=os.path.join(V, "ca.crt"))
    ctx.load_cert_chain(os.path.join(V, "client.crt"), os.path.join(V, "client.key"))
    ctx.check_hostname = False   # хранилище проверяется по сертификату от CA панели, имя может быть IP
    for v in vaults:
        st = status.get(str(v["id"]), {}); st["name"] = v["name"]; st["url"] = v["url"]; st["checked"] = int(time.time())
        try:
            if not newest:
                st["error"] = "нет зашифрованных копий: создайте ключ шифрования в панели"; status[str(v["id"])] = st; continue
            name = os.path.basename(newest)
            if st.get("last") != name:
                with open(newest, "rb") as f:
                    rq = urllib.request.Request(v["url"].rstrip("/") + "/upload/" + name, data=f, method="PUT",
                                                headers={"Content-Length": str(os.path.getsize(newest)), "Content-Type": "application/octet-stream"})
                    try: code = urllib.request.urlopen(rq, context=ctx, timeout=300).status
                    except urllib.error.HTTPError as e: code = e.code
                if code not in (201, 409): raise IOError(f"загрузка: HTTP {code}")
                st["last"] = name; st["last_ts"] = int(time.time())
            lst = json.load(urllib.request.urlopen(urllib.request.Request(v["url"].rstrip("/") + "/list"), context=ctx, timeout=30))
            st.update(ok=True, error="", count=len(lst["files"]), total=lst["total"], free=lst["free"], newest=(lst["files"][0]["name"] if lst["files"] else ""))
        except Exception as e:
            st.update(ok=False, error=str(e)[:300])
        status[str(v["id"])] = st
    ids = {str(v["id"]) for v in vaults}
    status = {k: s for k, s in status.items() if k in ids}
    tmp = os.path.join(V, ".status.tmp")
    with open(tmp, "w") as f: json.dump(status, f, ensure_ascii=False)
    os.replace(tmp, os.path.join(V, "status.json"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else C)
