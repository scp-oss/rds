#!/bin/sh
# Копии базы панели RDS: <каталог>/rds-ГГГГММДД-ЧЧММ.sql.gz (полный pg_dump).
# Запускается таймером rds-pg-backup.timer каждые 15 минут; настройки — в панели (☰ → Резервные копии), таблица settings:
#   backup_dir       — куда класть дампы (по умолчанию /opt/RDS/data/backup); только внутри /mnt /media /srv /backup /home /opt/RDS/data
#   backup_every_h   — как часто делать копию, часов (24)
#   backup_keep_days — сколько дней хранить (14)
#   backup_max_mb    — предельный общий размер копий, МБ (2048): сверх него удаляются самые старые
# Самая свежая копия не удаляется никогда; удаляются только файлы rds-*.sql.gz.
# Служебный каталог C (виден панели как /data/backup): .request — «Сделать копию сейчас», .status — итог, .index.json — список копий.
# Шифрование: если панель создала ключ (☰ → Резервные копии → Шифрование), в $C/.age-recipient лежит ОТКРЫТЫЙ ключ age —
# копия сразу пишется как rds-….sql.gz.age (незашифрованная на диск не попадает). Расшифровка: age -d -i ключ.txt файл.age | gunzip > dump.sql
# Затем vault-push.py отправляет самую свежую зашифрованную копию во внешние хранилища rds-vault.
# Ручной запуск: sh pg-backup.sh force
set -eu
C=/opt/RDS/data/backup; mkdir -p "$C"; chmod 700 "$C"; umask 077
Q() { docker exec rds-postgres psql -h 127.0.0.1 -p 5433 -U rds -d rds -tAc "$1" 2>/dev/null || true; }
num() { v=$(Q "select v from settings where k='$1'" | tr -dc 0-9); [ -n "$v" ] && [ "$v" -gt 0 ] && echo "$v" || echo "$2"; }
EVERY_H=$(num backup_every_h 24); KEEP_D=$(num backup_keep_days 14); MAX_MB=$(num backup_max_mb 2048)
NOW=$(date +%s); ERR=""
D=$(Q "select v from settings where k='backup_dir'" | head -1 | tr -d '\r')
case "$D" in
  "") D=$C ;;
  *..*|*//*) ERR="недопустимый каталог: $D"; D=$C ;;
  /mnt/?*|/media/?*|/srv/?*|/backup|/backup/*|/home/?*|/opt/RDS/data/backup|/opt/RDS/data/backup/*) ;;
  *) ERR="каталог вне разрешённых (/mnt /media /srv /backup /home /opt/RDS/data/backup): $D"; D=$C ;;
esac
printf '%s' "$D" | grep -q '^/[A-Za-z0-9._/-]*$' || { ERR="недопустимые символы в пути: $D"; D=$C; }
if ! mkdir -p "$D" 2>/dev/null || ! [ -w "$D" ]; then ERR="каталог недоступен для записи: $D"; D=$C; mkdir -p "$D"; fi
[ "$D" = "$C" ] || chmod 700 "$D" 2>/dev/null || true
R=""; [ -f "$C/.age-recipient" ] && R=$(tr -dc 'a-z0-9' < "$C/.age-recipient")
case "$R" in age1*) command -v age >/dev/null 2>&1 || { ERR="не установлен age — копии не шифруются"; R=""; } ;; *) R="" ;; esac
LAST=$(ls -1t "$D"/rds-*.sql.gz* 2>/dev/null | head -1 || true)
LAST_T=0; [ -n "$LAST" ] && LAST_T=$(stat -c %Y "$LAST")
DUE=0
[ "${1:-}" = force ] && DUE=1
[ -f "$C/.request" ] && DUE=1
[ $((NOW - LAST_T)) -ge $((EVERY_H * 3600 - 600)) ] && DUE=1
if [ "$DUE" = 1 ]; then
  F="$D/rds-$(date +%Y%m%d-%H%M).sql.gz"; [ -n "$R" ] && F="$F.age"
  enc() { if [ -n "$R" ]; then age -r "$R"; else cat; fi; }
  if docker exec rds-postgres pg_dump -h 127.0.0.1 -p 5433 -U rds -d rds --clean --if-exists | gzip | enc > "$F.tmp" && [ -s "$F.tmp" ]; then
    mv "$F.tmp" "$F"; rm -f "$C/.request"
    printf '{"ok":true,"ts":%s,"file":"%s","size":%s,"dir":"%s","warn":"%s"}\n' "$NOW" "$(basename "$F")" "$(stat -c %s "$F")" "$D" "$ERR" > "$C/.status"
  else
    rm -f "$F.tmp"
    printf '{"ok":false,"ts":%s,"error":"pg_dump не удался","dir":"%s","warn":"%s"}\n' "$NOW" "$D" "$ERR" > "$C/.status"
  fi
fi
# чистка: старше KEEP_D дней и сверх MAX_MB (самые старые первыми), самая свежая остаётся всегда
NEWEST=$(ls -1t "$D"/rds-*.sql.gz* 2>/dev/null | head -1 || true)
for f in $(ls -1tr "$D"/rds-*.sql.gz* 2>/dev/null); do
  [ "$f" = "$NEWEST" ] && continue
  [ $(( (NOW - $(stat -c %Y "$f")) / 86400 )) -ge "$KEEP_D" ] && rm -f "$f"
done
while :; do
  TOTAL=$(du -cb "$D"/rds-*.sql.gz* 2>/dev/null | tail -1 | cut -f1); TOTAL=${TOTAL:-0}
  [ "$TOTAL" -le $((MAX_MB * 1048576)) ] && break
  OLD=$(ls -1tr "$D"/rds-*.sql.gz* 2>/dev/null | head -1)
  [ -z "$OLD" ] || [ "$OLD" = "$NEWEST" ] && break
  rm -f "$OLD"
done
# внешние хранилища (только зашифрованные копии)
[ -f "$C/.vault/vaults.json" ] && /usr/bin/python3 /opt/RDS/vault-push.py "$D" || true
# список копий и свободное место — для панели
FREE=$(df -B1 --output=avail "$D" 2>/dev/null | tail -1 | tr -dc 0-9)
{ printf '{"dir":"%s","warn":"%s","free":%s,"files":[' "$D" "$ERR" "${FREE:-0}"; n=0
  for f in $(ls -1t "$D"/rds-*.sql.gz* 2>/dev/null); do
    [ $n -gt 0 ] && printf ','; printf '{"name":"%s","size":%s,"ts":%s}' "$(basename "$f")" "$(stat -c %s "$f")" "$(stat -c %Y "$f")"; n=$((n+1))
  done; printf ']}\n'; } > "$C/.index.json.tmp" && mv "$C/.index.json.tmp" "$C/.index.json"
