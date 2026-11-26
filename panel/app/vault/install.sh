#!/bin/sh
# Установка хранилища копий rds-vault (Docker). Команду с VAULT_SECRET выдаёт панель RDS: ☰ → Резервные копии → Хранилища → Добавить.
#   curl -fsSL __BASE__/vault/install.sh | sudo VAULT_SECRET=… VAULT_PORT=8743 VAULT_DIR=/mnt/disk/rds-vault sh
# Необязательно: VAULT_KEEP_DAYS (90), VAULT_MAX_MB (51200).
set -eu
[ -n "${VAULT_SECRET:-}" ] || { echo "Нет VAULT_SECRET — возьмите команду в панели RDS"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Нужен Docker"; exit 1; }
PORT=${VAULT_PORT:-8743}; DIR=${VAULT_DIR:-/opt/rds-vault/data}; KEEP=${VAULT_KEEP_DAYS:-90}; MAXMB=${VAULT_MAX_MB:-51200}
case "$DIR" in /*) ;; *) echo "VAULT_DIR — абсолютный путь"; exit 1;; esac
APP=/opt/rds-vault; mkdir -p "$APP" "$DIR"; chmod 700 "$APP"
curl -fsSL "__BASE__/vault/vault.py" -o "$APP/vault.py.new" && head -1 "$APP/vault.py.new" | grep -q python3 && mv "$APP/vault.py.new" "$APP/vault.py"
chmod 644 "$APP/vault.py"
chown 65534:65534 "$DIR"; chmod 700 "$DIR"
umask 077
cat > "$APP/.env" <<EOF
VAULT_SECRET=$VAULT_SECRET
VAULT_PORT=$PORT
VAULT_KEEP_DAYS=$KEEP
VAULT_MAX_MB=$MAXMB
EOF
cat > "$APP/compose.yaml" <<EOF
# rds-vault: хранилище зашифрованных копий базы RDS (только приём и список, взаимный TLS с сертификатом панели)
services:
  rds-vault:
    image: python:3.12-alpine
    container_name: rds-vault
    command: ["python", "/app/vault.py"]
    env_file: .env
    environment: [ "VAULT_DATA=/data" ]
    volumes: [ "$APP/vault.py:/app/vault.py:ro", "$DIR:/data" ]
    ports: [ "$PORT:$PORT" ]
    user: "65534:65534"
    read_only: true
    tmpfs: [ "/tmp" ]
    cap_drop: [ ALL ]
    security_opt: [ "no-new-privileges:true" ]
    restart: unless-stopped
EOF
cd "$APP" && docker compose up -d
sleep 3; docker logs --tail 3 rds-vault
echo "Готово: rds-vault на порту $PORT, копии в $DIR. Панель увидит хранилище после следующей копии (или кнопки «Сделать копию сейчас»)."
