#!/bin/sh
# Установка / обновление RDS. Запуск от root из /opt/RDS:
#   RDS_HOST=rds.example.com CLIENT_HOST=rd.example.com ./install.sh
# Повторный запуск безопасен: существующий .env и data/ не трогаются, образы обновляются.
set -eu
DIR=/opt/RDS
die() { echo "ОШИБКА: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "запускайте от root"
[ "$(cd "$(dirname "$0")" && pwd)" = "$DIR" ] || die "репозиторий должен лежать в $DIR (пути зашиты в скрипты копий)"
cd "$DIR"
command -v docker >/dev/null || die "нет Docker: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "нет плагина docker compose"

rnd() { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
NEWPW=""
if [ ! -f .env ]; then
  H=${RDS_HOST:-}; C=${CLIENT_HOST:-}
  if [ -z "$H" ] && [ -t 0 ]; then printf 'Имя ID-сервера и админки (A-запись на этот сервер, напр. rds.example.com): '; read -r H; fi
  if [ -z "$C" ] && [ -t 0 ]; then printf 'Имя страницы установки клиентов [%s]: ' "$H"; read -r C; fi
  [ -n "$H" ] || die "не задан RDS_HOST"
  C=${C:-$H}
  printf '%s' "$H$C" | grep -qE '^[A-Za-z0-9.-]+$' || die "имя хоста: только латиница, цифры, точка, дефис"
  NEWPW=$(rnd 20)
  umask 077
  sed -e "s/^RDS_HOST=.*/RDS_HOST=$H/" -e "s/^ADMIN_HOST=.*/ADMIN_HOST=$H/" -e "s/^CLIENT_HOST=.*/CLIENT_HOST=$C/" \
      -e "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$NEWPW/" -e "s/^SECRET_KEY=.*/SECRET_KEY=$(rnd 64)/" \
      -e "s/^REG_TOKEN=.*/REG_TOKEN=$(rnd 48)/" -e "s/^PG_PASSWORD=.*/PG_PASSWORD=$(rnd 32)/" \
      -e "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(rnd 32)/" .env.example > .env
  umask 022
  echo "Создан .env (chmod 600)."
fi
chmod 600 .env
mkdir -p data && chmod 700 data

for p in 21114 21115 21116 21117 21118 21119 5433 6380; do
  if ss -ltnH "sport = :$p" 2>/dev/null | grep -q . && ! docker ps --format '{{.Names}}' | grep -qE '^(hbbs|hbbr|rds-panel|rds-postgres|rds-redis)$'; then
    die "порт $p уже занят другим процессом (ss -ltnp 'sport = :$p')"
  fi
done

docker compose pull --ignore-pull-failures
docker compose up -d
# ключ сервера и база hbbs создаются при первом старте — только root
sleep 3; chmod 600 data/id_ed25519 data/db_v2.sqlite3* 2>/dev/null || true

# копии базы: таймер systemd (настройки расписания — в панели)
if command -v systemctl >/dev/null; then
  install -m 644 deploy/rds-pg-backup.service deploy/rds-pg-backup.timer /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now rds-pg-backup.timer >/dev/null
  echo "Таймер копий базы: rds-pg-backup.timer (каждые 15 мин проверяет расписание из панели)."
fi
command -v age >/dev/null || echo "Совет: apt install age — для шифрования копий (ключ создаётся в панели)."

echo "Ожидание панели..."
i=0; until curl -fsS -o /dev/null http://127.0.0.1:21114/api/time 2>/dev/null; do i=$((i+1)); [ $i -gt 60 ] && die "панель не ответила за 2 мин: docker compose logs panel"; sleep 2; done
. ./.env
echo
echo "Готово. Ключ сервера (для клиентов): $(cat data/id_ed25519.pub 2>/dev/null || echo 'появится после первого старта hbbs')"
echo "Дальше: обратный прокси с HTTPS на 127.0.0.1:21114 для $ADMIN_HOST и $CLIENT_HOST (deploy/Caddyfile.example);"
echo "        открыть наружу 21115-21119/tcp и 21116/udp."
if [ -n "$NEWPW" ]; then
  echo
  echo "Вход в админку: https://$ADMIN_HOST  логин: ${ADMIN_USER:-admin}  пароль: $NEWPW"
  echo "Пароль показан один раз (он же в .env). Смените его в панели и включите 2FA."
fi
