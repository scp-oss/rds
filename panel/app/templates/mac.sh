#!/bin/bash
# RustDesk NETH для macOS: установка, настройка сервера, пароль, регистрация в панели.
# Запуск: двойной щелчок по «Install RustDesk.command» в образе .dmg
#     или: curl -fsSL __BASE__/mac.sh__Q__ | sudo bash
set -e
BASE='__BASE__'; API='__API__'; CFG='__CFG__'; TOKEN='__TOKEN__'; MASTER=__MASTER__
if [ "$(id -u)" -ne 0 ]; then
  echo "Нужны права администратора — введите пароль от Mac."
  exec sudo /bin/bash "$0" "$@"
fi
case "$(uname -m)" in arm64) A=aarch64;; x86_64) A=x86_64;; *) echo "Неподдерживаемый процессор $(uname -m)"; exit 1;; esac
U=${SUDO_USER:-$(stat -f %Su /dev/console)}; UID_=$(id -u "$U")
T=$(mktemp -d)
echo "Скачиваю RustDesk ($A)..."
# 1) GitHub (последний релиз), 2) кеш на сервере RDS (там хранится только последняя версия)
GH=$(curl -fsSL -m 15 https://api.github.com/repos/rustdesk/rustdesk/releases/latest 2>/dev/null \
     | grep -oE "https://[^\"]*/rustdesk-[0-9.]+-$A\.dmg" | head -1 || true)
if [ -z "$GH" ] || ! curl -fL -m 600 --progress-bar -o "$T/rd.dmg" "$GH"; then
  echo "GitHub недоступен, качаю с сервера..."
  curl -fL --progress-bar -o "$T/rd.dmg" "$BASE/dl/official/rustdesk-latest-$A.dmg"
fi
R=https://raw.githubusercontent.com/rustdesk/rustdesk/master/src/platform/privileges_scripts
for f in agent daemon; do
  curl -fsSL -m 15 -o "$T/$f.plist" "$R/$f.plist" 2>/dev/null || curl -fsSL -o "$T/$f.plist" "$BASE/dl/official/$f.plist"
done
MP="$T/mnt"; mkdir -p "$MP"
hdiutil attach -nobrowse -noautoopen -mountpoint "$MP" "$T/rd.dmg" >/dev/null
pkill -x RustDesk 2>/dev/null || true
rm -rf /Applications/RustDesk.app
cp -R "$MP/RustDesk.app" /Applications/
hdiutil detach "$MP" -quiet || true
xattr -dr com.apple.quarantine /Applications/RustDesk.app 2>/dev/null || true
RD0=/Applications/RustDesk.app/Contents/MacOS/RustDesk
# CLI RustDesk — только с HOME root: иначе он пишет root-файлы в профиль пользователя, и служба отклоняет смену пароля
RD=/tmp/rds-rd.$$; printf '#!/bin/sh\nHOME=/var/root exec "%s" "$@"\n' "$RD0" > "$RD"; chmod 755 "$RD"
fixprefs() { PD="$(eval echo ~"$U")/Library/Preferences/com.carriez.RustDesk"; [ -d "$PD" ] && chown -R "$U":staff "$PD" 2>/dev/null || true; }
trap 'rm -f "$RD"; fixprefs' EXIT

echo "Регистрирую службу RustDesk..."
AG=/Library/LaunchAgents/com.carriez.RustDesk_server.plist
DM=/Library/LaunchDaemons/com.carriez.RustDesk_service.plist
cp "$T/agent.plist" "$AG"; cp "$T/daemon.plist" "$DM"; chown 0:0 "$AG" "$DM"; chmod 644 "$AG" "$DM"
launchctl bootout system/com.carriez.RustDesk_service 2>/dev/null || true
launchctl bootstrap system "$DM" 2>/dev/null || launchctl load -w "$DM"
launchctl enable system/com.carriez.RustDesk_service 2>/dev/null || true
launchctl bootout "gui/$UID_/com.carriez.RustDesk_server" 2>/dev/null || true
launchctl bootstrap "gui/$UID_" "$AG" 2>/dev/null || true
sleep 5
# RD_UPDATE_ONLY=1 — обновление по кнопке из панели: только приложение и службы, настройки/пароль/регистрацию не трогаем
if [ -n "${RD_UPDATE_ONLY:-}" ]; then rm -rf "$T"; echo "RustDesk обновлён: $(defaults read /Applications/RustDesk.app/Contents/Info CFBundleShortVersionString 2>/dev/null)"; exit 0; fi

echo "Настраиваю сервер..."
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
ID=""
for i in $(seq 1 30); do ID=$("$RD" --get-id 2>/dev/null | tr -dc 0-9); [ -n "$ID" ] && break; sleep 2; done
M=false; [ -n "$PW" ] && M=true
# локальный IP — интерфейс маршрута по умолчанию; внешний — rd01/whoami (Cloudflare видит настоящий адрес)
IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}'); LIP=$(ipconfig getifaddr "${IF:-en0}" 2>/dev/null | tr -dc 0-9.)
EIP=$(curl -fsS -m 10 "$BASE/whoami" 2>/dev/null | tr -dc '0-9a-fA-F.:')
MAC=$(ifconfig "${IF:-en0}" 2>/dev/null | awk '/ether /{print $2; exit}')
pmset -a womp 1 >/dev/null 2>&1   # «Пробуждение для доступа по сети»
AK=$(tr -dc 'A-Za-z0-9_-' < "/Library/Application Support/RustDeskNETH/agent.key" 2>/dev/null | cut -c1-100)   # переустановка: ключ агента
J=$(printf '{"token":"%s","akey":"%s","id":"%s","hostname":"%s","username":"%s","os":"macos","master":%s,"password":"%s","local_ip":"%s","ext_ip":"%s","mac":"%s","want_master":%s}' \
     "$TOKEN" "$AK" "$ID" "$(scutil --get ComputerName 2>/dev/null | sed 's/["\\]//g')" "$U" "$M" "$PW" "$LIP" "$EIP" "$MAC" "$([ "$MASTER" = 1 ] && echo true || echo false)")
if curl -fsS -m 20 -H 'Content-Type: application/json' -d "$J" "$API/api/rds/register" >/dev/null; then
  curl -fsSL -m 30 "$BASE/hw.sh" 2>/dev/null | RD_ID="$ID" sh >/dev/null 2>&1 || true   # железо
  echo; echo "Готово. Ваш ID: $ID"
else
  echo; echo "RustDesk установлен, но сервер не ответил. Перешлите администратору: ID $ID ${PW:+пароль $PW}"
fi
rm -rf "$T"
# --- мастер разрешений: окна по шагам открывают нужные разделы настроек, тумблер включает сам пользователь
UID_=$(id -u "$U" 2>/dev/null || echo 0)
G=/tmp/rds-permissions.sh
cat > "$G" <<'GUIDE'
#!/bin/bash
ID="$1"
SC='x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture'
AX='x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'
IM='x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent'
dlg() { osascript -e 'on run argv' -e 'activate' \
  -e 'display dialog (item 1 of argv) buttons {(item 2 of argv)} default button 1 with title (item 3 of argv) with icon note' \
  -e 'end run' "$1" "$2" "$3" >/dev/null 2>&1; }
open -g /Applications/RustDesk.app; sleep 3      # RustDesk сам запросит доступ и появится в списках настроек
dlg "RustDesk установлен и подключён к серверу.

Ваш ID: $ID

Чтобы специалист мог видеть экран и управлять мышью и клавиатурой, macOS требует три разрешения. Сейчас по очереди откроются нужные настройки — останется включить переключатель." "Настроить" "RustDesk"
open "$SC"; sleep 1
dlg "Шаг 1 из 3 — «Запись экрана и системного звука»

В открывшемся окне настроек включите переключатель напротив RustDesk.

Если RustDesk нет в списке, нажмите «+» внизу и выберите Программы → RustDesk.
Если macOS предложит перезапустить RustDesk — нажмите «Выйти и открыть снова»." "Готово, дальше" "RustDesk — разрешения"
open "$AX"; sleep 1
dlg "Шаг 2 из 3 — «Универсальный доступ» (управление мышью)

Включите переключатель напротив RustDesk (macOS может попросить пароль от Mac).

Если RustDesk нет в списке, нажмите «+» и выберите Программы → RustDesk." "Готово, дальше" "RustDesk — разрешения"
open "$IM"; sleep 1
dlg "Шаг 3 из 3 — «Мониторинг ввода» (клавиатура)

Включите переключатель напротив RustDesk.

Если RustDesk нет в списке, нажмите «+» и выберите Программы → RustDesk.
Если macOS предложит перезапустить RustDesk — нажмите «Выйти и открыть снова»." "Готово" "RustDesk — разрешения"
open /Applications/RustDesk.app
dlg "Всё готово!

Сообщите специалисту ваш ID: $ID

Разрешения можно проверить в любой момент: Системные настройки → Конфиденциальность и безопасность." "OK" "RustDesk"
rm -f "$0"
GUIDE
chmod 755 "$G"; chown "$U" "$G" 2>/dev/null || true
if [ "$UID_" != 0 ] && [ -n "$ID" ]; then
  launchctl asuser "$UID_" sudo -u "$U" /bin/bash "$G" "$ID" >/dev/null 2>&1 &
  echo "Дальше следуйте подсказкам на экране: нужно включить RustDesk в «Записи экрана», «Универсальном доступе» и «Мониторинге ввода»."
else
  sudo -u "$U" open /Applications/RustDesk.app || true
  echo "Откройте Системные настройки → Конфиденциальность и безопасность и разрешите RustDesk"
  echo "«Запись экрана», «Универсальный доступ» и «Мониторинг ввода», иначе управление не заработает."
fi
