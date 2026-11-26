#!/bin/sh
# RustDesk NETH для Linux: настройка сервера, пароль, регистрация в панели.
# Вызывается из postinst пакета rustdesk-neth (от root, после запуска службы).
API='__API__'; CFG='__CFG__'; TOKEN='__TOKEN__'; MASTER=__MASTER__
RD=/usr/bin/rustdesk
[ -x "$RD" ] || RD=$(command -v rustdesk)
systemctl start rustdesk 2>/dev/null || true
ID=""
for i in $(seq 1 30); do ID=$("$RD" --get-id 2>/dev/null | tr -dc 0-9); [ -n "$ID" ] && break; sleep 2; done
RH='__RDS__'
for i in $(seq 1 20); do "$RD" --config "$CFG" >/dev/null 2>&1; [ "$("$RD" --option custom-rendezvous-server 2>/dev/null | tr -d '\r\n')" = "$RH" ] && break; sleep 2; done
# служба после установки/обновления перезапускается — повторяем, пока RustDesk не подтвердит
setopt() { for i in $(seq 1 20); do "$RD" --option "$1" "$2" >/dev/null 2>&1; [ "$("$RD" --option "$1" 2>/dev/null | tr -d '\r\n')" = "$2" ] && return 0; sleep 2; done; return 1; }
PW=""
if [ "$MASTER" = 1 ]; then
  P=$(LC_ALL=C tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789' </dev/urandom | head -c 14)
  for i in $(seq 1 20); do "$RD" --password "$P" 2>&1 | grep -q 'Done' && { PW=$P; break; }; sleep 2; done
  [ -n "$PW" ] || echo "ВНИМАНИЕ: не удалось установить постоянный пароль — доступ только по одноразовому"
  setopt verification-method use-both-passwords || true
else
  setopt verification-method use-temporary-password || true
fi
[ -n "$ID" ] || ID=$("$RD" --get-id 2>/dev/null | tr -dc 0-9)
U=$(logname 2>/dev/null || echo "${SUDO_USER:-}")
H=$(hostname 2>/dev/null | sed 's/["\\]//g')
M=false; [ -n "$PW" ] && M=true
# локальный IP — адрес маршрута по умолчанию; внешний — rd01/whoami (Cloudflare видит настоящий адрес)
LIP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$LIP" ] || LIP=$(hostname -I 2>/dev/null | awk '{print $1}')
DEV=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
MAC=$(cat "/sys/class/net/${DEV:-none}/address" 2>/dev/null)
command -v ethtool >/dev/null 2>&1 && [ -n "$DEV" ] && ethtool -s "$DEV" wol g >/dev/null 2>&1   # Wake-on-LAN, если карта умеет
EIP=""; BASE='__BASE__'
if command -v curl >/dev/null 2>&1; then EIP=$(curl -fsS -m 10 "$BASE/whoami" 2>/dev/null); elif command -v wget >/dev/null 2>&1; then EIP=$(wget -qO- -T 10 "$BASE/whoami" 2>/dev/null); fi
EIP=$(printf '%s' "$EIP" | tr -dc '0-9a-fA-F.:')
AK=$(tr -dc 'A-Za-z0-9_-' < /usr/local/lib/rustdesk-neth/agent.key 2>/dev/null | cut -c1-100)   # переустановка: ключ агента этого ПК
J=$(printf '{"token":"%s","akey":"%s","id":"%s","hostname":"%s","username":"%s","os":"linux","master":%s,"password":"%s","local_ip":"%s","ext_ip":"%s","mac":"%s","want_master":%s}' "$TOKEN" "$AK" "$ID" "$H" "$U" "$M" "$PW" "$LIP" "$EIP" "$MAC" "$([ "$MASTER" = 1 ] && echo true || echo false)")
OK=0
if command -v curl >/dev/null 2>&1; then
  curl -fsS -m 20 -H 'Content-Type: application/json' -d "$J" "$API/api/rds/register" >/dev/null 2>&1 && OK=1
elif command -v wget >/dev/null 2>&1; then
  wget -q -T 20 -O /dev/null --header='Content-Type: application/json' --post-data="$J" "$API/api/rds/register" && OK=1
elif command -v python3 >/dev/null 2>&1; then
  python3 -c "import sys,urllib.request as u;u.urlopen(u.Request(sys.argv[1],sys.argv[2].encode(),{'Content-Type':'application/json'}),timeout=20)" "$API/api/rds/register" "$J" && OK=1
fi
# железо (процессор, память, диски, сетевая карта) — тот же скрипт, что и команда «обновить данные»
if command -v curl >/dev/null 2>&1; then curl -fsSL -m 30 "$BASE/hw.sh" 2>/dev/null | RD_ID="$ID" sh >/dev/null 2>&1; elif command -v wget >/dev/null 2>&1; then wget -qO- -T 30 "$BASE/hw.sh" 2>/dev/null | RD_ID="$ID" sh >/dev/null 2>&1; fi
echo "=================================================="
if [ $OK = 1 ]; then echo "RustDesk настроен. Ваш ID: $ID"
else echo "RustDesk установлен, но сервер не ответил. Перешлите администратору: ID $ID ${PW:+пароль $PW}"; fi
echo "=================================================="
exit 0
