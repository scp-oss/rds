#!/bin/sh
# RustDesk NETH: обновить в панели железо, принтеры, пользователей, IP и MAC этого ПК БЕЗ переустановки RustDesk (Linux и macOS).
#   curl -fsSL __BASE__/hw.sh | sudo sh
# От root заодно ставит автообновление: при загрузке и каждые 12 ч (Linux — таймер systemd, macOS — LaunchDaemon),
# чтобы панель замечала замену железа. RD_HW_TASK=1 — запуск из этого расписания (без переустановки расписания).
API='__API__'; BASE='__BASE__'; TOKEN='__TOKEN__'; HWV='__HWV__'
# ключ агента: панель выдаёт его этому ПК один раз (akey_new), дальше общий TOKEN для этого ПК не принимается.
# Хранится только у root (0600); без root скрипт не просит ключ (ak=0), чтобы не потерять его.
AKDIR=/usr/local/lib/rustdesk-neth; [ "$(uname -s)" = Darwin ] && AKDIR="/Library/Application Support/RustDeskNETH"
AKF="$AKDIR/agent.key"; AK=""; AKC=0
if [ "$(id -u)" = 0 ]; then AKC=1; [ -r "$AKF" ] && AK=$(tr -dc 'A-Za-z0-9_-' < "$AKF" | cut -c1-100); fi
auth() { printf '"token":"%s","akey":"%s","ak":%s' "$TOKEN" "$AK" "$AKC"; }
akey_save() { [ "$AKC" = 1 ] || return 0; K=$(printf '%s' "$1" | sed -n 's/.*"akey_new":"\([A-Za-z0-9_-]\{20,100\}\)".*/\1/p' | head -1); [ -n "$K" ] || return 0
  mkdir -p "$AKDIR" && (umask 077; printf '%s' "$K" > "$AKF.tmp") && mv -f "$AKF.tmp" "$AKF" && chmod 600 "$AKF" && AK="$K"; }
js() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
say() { [ -n "${RD_HW_TASK:-}" ] || echo "$*"; }
GMEM=""; BV=""; BN=""; CORES=""; THR=""; RTYPE=""; BTN=""; BTS=""; CPU=""; GPU=""; RAM=""; DISK=""; NT=""; SPD=""; NICN=""; MAC=""; LIP=""; USERS=""; LOGGED=""; ID="${RD_ID:-}"; PR=""
arp_mac() { ping -c 1 -W 1 "$1" >/dev/null 2>&1 || ping -c 1 -t 1 "$1" >/dev/null 2>&1
  { ip neigh show "$1" 2>/dev/null; arp -n "$1" 2>/dev/null; } | grep -oiE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}' | head -1 | tr 'A-F' 'a-f'; }
get() { if command -v curl >/dev/null 2>&1; then curl -fsSL -m 60 "$1"; else wget -qO- -T 60 "$1"; fi; }
postq() { if command -v curl >/dev/null 2>&1; then curl -fsS -m 20 -H 'Content-Type: application/json' -d "$2" "$1"; else wget -qO- -T 20 --header='Content-Type: application/json' --post-data="$2" "$1"; fi; }
rd_id() { if [ "$(uname -s)" = Darwin ]; then HOME=/var/root /Applications/RustDesk.app/Contents/MacOS/RustDesk --get-id 2>/dev/null; else "$(command -v rustdesk || echo /usr/bin/rustdesk)" --get-id 2>/dev/null; fi | tr -dc 0-9; }
# RD_POLL=1 — каждую минуту (таймер/LaunchDaemon): спросить панель, нет ли команды (обновить RustDesk / выключить / перезагрузить)
# задания «Программы» из панели (установка / обновление / удаление); все значения приходят в base64
sw_job() {
  R="$1"
  jf() { printf '%s' "$R" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
  d64() { v=$(jf "$1_b64"); [ -n "$v" ] || return 0; printf '%s' "$v" | base64 -d 2>/dev/null || printf '%s' "$v" | base64 -D 2>/dev/null; }
  JID=$(jf id); ACT=$(jf act); KIND=$(jf kind); SHA=$(jf sha)
  SRC=$(d64 src); IA=$(d64 args); UA=$(d64 uargs); NM=$(d64 name); URL=$(d64 url); CFG=$(d64 cfg); POST=$(d64 post)
  LOG="/tmp/rds-job-$JID.log"; : > "$LOG"
  PM=""; for p in apt-get dnf yum zypper pacman; do command -v $p >/dev/null 2>&1 && { PM=$p; break; }; done
  pkgcmd() {   # $1 install|upgrade|uninstall, $2 пакеты, $3 доп. параметры
    case "$PM" in
      apt-get) export DEBIAN_FRONTEND=noninteractive
        case "$1" in install) apt-get update -q && apt-get install -y -q $3 $2;; upgrade) apt-get update -q && apt-get install -y -q --only-upgrade $3 $2;; uninstall) apt-get remove -y -q $3 $2;; esac;;
      dnf|yum) case "$1" in install) $PM install -y $3 $2;; upgrade) $PM upgrade -y $3 $2;; uninstall) $PM remove -y $3 $2;; esac;;
      zypper) case "$1" in install) zypper -n install $3 $2;; upgrade) zypper -n update $3 $2;; uninstall) zypper -n remove $3 $2;; esac;;
      pacman) case "$1" in install|upgrade) pacman -S --noconfirm $3 $2;; uninstall) pacman -R --noconfirm $3 $2;; esac;;
      *) echo "no package manager found"; return 127;;
    esac; }
  runscript() { F="/tmp/rds-job-$JID-$$.sh"; printf '%s\n' "$1" > "$F"; chmod 700 "$F"
    if command -v bash >/dev/null 2>&1; then bash "$F" $2; else sh "$F" $2; fi; RS=$?; rm -f "$F"; return $RS; }
  sw_do() {
    case "$KIND" in
      pkg)
        if [ "$ACT" = uninstall ]; then pkgcmd uninstall "$SRC" "$UA"; return $?; fi
        if [ -n "$CFG" ] && [ "$PM" = apt-get ] && command -v debconf-set-selections >/dev/null 2>&1; then printf '%s\n' "$CFG" | debconf-set-selections || return $?; fi
        pkgcmd "$ACT" "$SRC" "$IA";;
      script)
        if [ "$ACT" = uninstall ]; then [ -n "$UA" ] || { echo "no uninstall script"; return 2; }; runscript "$UA" ""; else runscript "$SRC" "$IA"; fi;;
      macpkg)
        if [ "$ACT" = uninstall ]; then if [ -n "$UA" ]; then runscript "$UA" ""; else rm -rf "/Applications/$NM.app"; fi; return $?; fi
        [ -n "$URL" ] || { echo "no installer file or URL"; return 2; }
        F="/tmp/rds-job-$JID.pkg"; curl -fsSL "$URL" -o "$F" || return $?
        if [ -n "$SHA" ]; then H=$( (shasum -a 256 "$F" 2>/dev/null || sha256sum "$F") | awk '{print $1}'); [ "$H" = "$SHA" ] || { echo "checksum mismatch"; rm -f "$F"; return 3; }; fi
        installer -pkg "$F" -target /; RS=$?; rm -f "$F"; return $RS;;
      byname)
        if [ "$(uname -s)" = Darwin ]; then rm -rf "/Applications/$NM.app"; else pkgcmd uninstall "$NM" "$UA"; fi;;
      *) echo "unsupported job type: $KIND"; return 2;;
    esac; }
  sw_do >> "$LOG" 2>&1; RC=$?
  if [ "$RC" = 0 ] && [ "$ACT" != uninstall ] && [ -n "$POST" ]; then runscript "$POST" "" >> "$LOG" 2>&1; RC=$?; [ "$RC" = 0 ] || echo "post-install script failed" >> "$LOG"; fi
  OK=true; [ "$RC" = 0 ] || OK=false
  # последние осмысленные строки вывода (без прогресса apt «Чтение базы данных … 5%»)
  MSG=$(tr '\r' '\n' < "$LOG" 2>/dev/null | grep -vE '^[[:space:]]*$|^\((Reading|Чтение)|[0-9]+%$' | tail -2 | tr '\n' ' ' | cut -c1-300)
  J2=$(printf '{%s,"id":"%s","job":"%s","ok":%s,"code":"%s","msg":"%s"}' "$(auth)" "$ID" "$JID" "$OK" "$RC" "$(js "$MSG")")
  postq "$API/api/rds/jobresult" "$J2" >/dev/null 2>&1 || postq "$BASE/api/rds/jobresult" "$J2" >/dev/null 2>&1
  rm -f "$LOG"
}
# выключение/перезагрузка из панели: $1 shutdown|reboot, $2 задержка в секундах, $3 текст для пользователя
power_do() {
  A=$1; DL=$2; MSG=$3; MIN=$(( (DL + 59) / 60 )); F=-h; [ "$A" = reboot ] && F=-r
  if [ "$(uname -s)" = Darwin ]; then
    for U in $(who | awk '$2=="console"{print $1}' | sort -u); do
      launchctl asuser "$(id -u "$U")" sudo -u "$U" osascript - "$MSG" >/dev/null 2>&1 <<'OSA' &
on run argv
  display dialog (item 1 of argv) with title "RDS" buttons {"OK"} default button 1 with icon caution giving up after 600
end run
OSA
    done
    if [ "$DL" -le 0 ]; then shutdown $F now; else shutdown $F +$MIN "$MSG"; fi >/dev/null 2>&1
    return 0
  fi
  # окно на рабочем столе у каждого графического сеанса (notify-send, если установлен) + wall в терминалы
  if command -v loginctl >/dev/null 2>&1 && command -v notify-send >/dev/null 2>&1; then
    for S in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
      T=$(loginctl show-session "$S" -p Type --value 2>/dev/null); case "$T" in x11|wayland) ;; *) continue;; esac
      SU=$(loginctl show-session "$S" -p Name --value 2>/dev/null); SD=$(loginctl show-session "$S" -p Display --value 2>/dev/null); SI=$(id -u "$SU" 2>/dev/null) || continue
      runuser -u "$SU" -- env DISPLAY="${SD:-:0}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SI/bus" notify-send -u critical -a RDS "RDS" "$MSG" >/dev/null 2>&1 &
    done
  fi
  if [ "$DL" -le 0 ]; then wall "$MSG" 2>/dev/null; shutdown $F now >/dev/null 2>&1 || { [ "$A" = reboot ] && reboot || poweroff; }
  elif [ $((DL % 60)) -eq 0 ] && shutdown $F +$MIN "$MSG" >/dev/null 2>&1; then :
  elif command -v systemd-run >/dev/null 2>&1 && systemd-run --quiet --on-active="${DL}s" systemctl "$([ "$A" = reboot ] && echo reboot || echo poweroff)" >/dev/null 2>&1; then wall "$MSG" 2>/dev/null
  else shutdown $F +$MIN "$MSG" >/dev/null 2>&1; fi
  return 0
}
# api-server в RustDesk — как в панели (например, после переезда панели): заново применить конфиг сервера, не чаще раза в сутки
ensure_api() {
  [ "$(id -u)" = 0 ] || return 0
  if [ "$(uname -s)" = Darwin ]; then RDB=/Applications/RustDesk.app/Contents/MacOS/RustDesk; CF=/var/root/Library/Preferences/com.carriez.RustDesk/RustDesk2.toml
  else RDB=$(command -v rustdesk || echo /usr/bin/rustdesk); CF=/root/.config/rustdesk/RustDesk2.toml; fi
  [ -x "$RDB" ] && [ -f "$CF" ] || return 0
  CUR=$(sed -n "s/^api-server *= *'\([^']*\)'.*/\1/p" "$CF" | head -1)
  [ "$CUR" = "$API" ] && return 0
  SF="$AKDIR/cfg-applied"; NOW=$(date +%s); LAST=0; [ -f "$SF" ] && LAST=$(tr -dc 0-9 < "$SF"); LAST=${LAST:-0}
  [ $((NOW - LAST)) -ge 86400 ] || return 0
  mkdir -p "$AKDIR" && echo "$NOW" > "$SF"
  # служба держит настройки в памяти — после записи конфига её нужно перезапустить
  if [ "$(uname -s)" = Darwin ]; then HOME=/var/root "$RDB" --config '__CFG__' >/dev/null 2>&1; launchctl kickstart -k system/com.carriez.RustDesk_service >/dev/null 2>&1
  else "$RDB" --config '__CFG__' >/dev/null 2>&1; systemctl restart rustdesk >/dev/null 2>&1 || service rustdesk restart >/dev/null 2>&1; fi
  return 0
}
ensure_api
if [ -n "${RD_POLL:-}" ]; then
  ID=$(rd_id); [ -n "$ID" ] || exit 0
  if [ "$(uname -s)" = Darwin ]; then RDV=$(defaults read /Applications/RustDesk.app/Contents/Info CFBundleShortVersionString 2>/dev/null)
  else RDV=$("$(command -v rustdesk || echo /usr/bin/rustdesk)" --version 2>/dev/null | head -1); fi; RDV=$(printf '%s' "$RDV" | tr -dc 0-9.)
  Q=$(printf '{%s,"id":"%s","rdv":"%s"}' "$(auth)" "$ID" "$RDV")
  R=$(postq "$API/api/rds/poll" "$Q" 2>/dev/null || postq "$BASE/api/rds/poll" "$Q" 2>/dev/null)
  akey_save "$R"
  # «Обновить данные» из карточки Hardware и задания «Программы» (после задания — обновить список установленного ПО)
  case "$R" in *'"cmd":"hw"'*) RD_HW_TASK=1 RD_POLL= /bin/sh "$0" >/dev/null 2>&1; exit 0;; esac
  case "$R" in *'"job":{'*) sw_job "$R"; RD_HW_TASK=1 RD_POLL= /bin/sh "$0" >/dev/null 2>&1; exit 0;; esac
  case "$R" in
    *'"cmd":"shutdown"'*|*'"cmd":"reboot"'*)
      A=shutdown; case "$R" in *'"cmd":"reboot"'*) A=reboot;; esac
      DL=$(printf '%s' "$R" | sed -n 's/.*"delay":"\([0-9]*\)".*/\1/p'); [ -n "$DL" ] || DL=60
      MB=$(printf '%s' "$R" | sed -n 's/.*"msg_b64":"\([^"]*\)".*/\1/p')
      MSG=$(printf '%s' "$MB" | base64 -d 2>/dev/null || printf '%s' "$MB" | base64 -D 2>/dev/null)
      [ -n "$MSG" ] || MSG="Компьютер будет выключен по команде администратора (панель RDS). Сохраните работу."
      J2=$(printf '{%s,"id":"%s","ok":true,"action":"%s","msg":""}' "$(auth)" "$ID" "$A")
      postq "$API/api/rds/cmdresult" "$J2" >/dev/null 2>&1 || postq "$BASE/api/rds/cmdresult" "$J2" >/dev/null 2>&1
      power_do "$A" "$DL" "$MSG"
      exit 0;;
    *'"cmd":"update"'*) ;;
    *)
      # в панели новее сборщик — скачать и сразу собрать данные (одну и ту же версию — не чаще раза в 30 мин)
      W=$(printf '%s' "$R" | sed -n 's/.*"hwv_unix":"\([0-9a-f]*\)".*/\1/p')
      if [ -n "$W" ] && [ "$W" != "$HWV" ]; then
        for SELF in "/usr/local/lib/rustdesk-neth/hw.sh" "/Library/Application Support/RustDeskNETH/hw.sh"; do
          [ -f "$SELF" ] || continue
          MK="$(dirname "$SELF")/hwv.try"
          if [ -f "$MK" ] && [ "$(cat "$MK")" = "$W" ] && [ -n "$(find "$MK" -mmin -30 2>/dev/null)" ]; then break; fi
          printf '%s' "$W" > "$MK"
          get "$BASE/hw.sh" > "$SELF.new" 2>/dev/null && head -1 "$SELF.new" | grep -q '^#!/bin/sh' && [ "$(wc -c < "$SELF.new")" -gt 2000 ] && mv "$SELF.new" "$SELF" && chmod 700 "$SELF" || rm -f "$SELF.new"
          RD_HW_TASK=1 RD_POLL= /bin/sh "$SELF" >/dev/null 2>&1
          break
        done
      fi
      exit 0;;
  esac
  L=/var/log/rustdesk-neth-update.log
  if [ "$(uname -s)" = Darwin ]; then
    get "$BASE/mac.sh" > /tmp/rds-upd.sh 2>/dev/null && RD_UPDATE_ONLY=1 /bin/bash /tmp/rds-upd.sh > "$L" 2>&1; RC=$?; rm -f /tmp/rds-upd.sh
    VER=$(defaults read /Applications/RustDesk.app/Contents/Info CFBundleShortVersionString 2>/dev/null)
  else
    get "$BASE/linux.sh" 2>/dev/null | RD_UPDATE_ONLY=1 sh > "$L" 2>&1; RC=$?
    VER=$("$(command -v rustdesk || echo /usr/bin/rustdesk)" --version 2>/dev/null | head -1 | tr -dc 0-9.)
  fi
  OK=true; MSG=""; [ "$RC" = 0 ] || { OK=false; MSG=$(tail -3 "$L" 2>/dev/null | tr '\n' ' ' | cut -c1-200); }
  J2=$(printf '{%s,"id":"%s","ok":%s,"version":"%s","msg":"%s"}' "$(auth)" "$ID" "$OK" "$(js "$VER")" "$(js "$MSG")")
  postq "$API/api/rds/cmdresult" "$J2" >/dev/null 2>&1 || postq "$BASE/api/rds/cmdresult" "$J2" >/dev/null 2>&1
  exit 0
fi
# установленное ПО (Linux — пакеты, поставленные вручную, + flatpak/snap; macOS — /Applications) → JSON [{"n","v"}]
software() {
  TAB=$(printf '\t')
  { if [ "$(uname -s)" = Darwin ]; then
      for a in /Applications/*.app; do [ -d "$a" ] || continue
        printf '%s\t%s\n' "$(basename "$a" .app)" "$(defaults read "$a/Contents/Info" CFBundleShortVersionString 2>/dev/null)"; done
    elif command -v apt-mark >/dev/null 2>&1; then
      apt-mark showmanual 2>/dev/null | sort > /tmp/rds-m.$$
      dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort | join -t "$TAB" /tmp/rds-m.$$ - 2>/dev/null; rm -f /tmp/rds-m.$$
    elif command -v pacman >/dev/null 2>&1; then pacman -Qe 2>/dev/null | tr ' ' '\t'
    elif command -v dnf >/dev/null 2>&1; then timeout 60 dnf repoquery --userinstalled --qf '%{name}\t%{version}' 2>/dev/null
    elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}\n' 2>/dev/null; fi
    command -v flatpak >/dev/null 2>&1 && flatpak list --app --columns=name,version 2>/dev/null
    command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | awk 'NR>1{print $1"\t"$2}'
  } | awk -F'\t' 'NF>=1 && $1!="" && n<500 {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "%s{\"n\":\"%s\",\"v\":\"%s\"}", (n++?",":"["), $1, $2} END{printf "%s", (n?"]":"[]")}'
}
# принтеры CUPS (Linux и macOS): lpstat -v → «device for ИМЯ: uri»
printers() {
  command -v lpstat >/dev/null 2>&1 || { printf '[]'; return; }
  DEF=$(lpstat -d 2>/dev/null | sed -n 's/.*: *//p')
  # USB-принтеры, подключённые сейчас (lpinfo видит только присутствующие устройства; нужен root — агент работает от root)
  LPI=""; command -v lpinfo >/dev/null 2>&1 && LPI=$( (timeout 20 lpinfo --include-schemes usb -v 2>/dev/null || true) | awk '{print $2}'; echo checked)
  lpstat -v 2>/dev/null | sed -n 's/^device for \([^:]*\): *\(.*\)$/\1\t\2/p' | {
    n=0; printf '['
    while IFS='	' read -r name uri; do
      case "$name" in *PDF*|*pdf*) continue;; esac
      t=other; host=""
      case "$uri" in
        usb:*|parallel:*|hp:/usb*|*usb*) t=usb;;
        ipp:*|ipps:*|http:*|https:*|socket:*|lpd:*|dnssd:*|smb:*|hp:/net*|ldap:*) t=network; host=$(printf '%s' "$uri" | sed -n 's|^[a-z]*://\([^/:?]*\).*|\1|p');;
      esac
      case "$uri" in hp:/net*) host=$(printf '%s' "$uri" | sed -n 's/.*ip=\([0-9.]*\).*/\1/p');; esac
      ip=""; mac=""
      case "$host" in
        *[!0-9.]*) ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}'); [ -n "$ip" ] || ip=$(ping -c1 -t1 "$host" 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p' | head -1); [ -n "$ip" ] || ip="$host";;
        *) ip="$host";;
      esac
      case "$ip" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) mac=$(arp_mac "$ip");; esac
      d=false; [ "$name" = "$DEF" ] && d=true
      # состояние: offline_mode — очередь приостановлена (disabled), disconnected — USB-принтера нет среди подключённых
      st=ok
      if lpstat -p "$name" 2>/dev/null | grep -qi 'disabled\|отключен'; then st=offline_mode
      elif [ -n "$LPI" ]; then case "$uri" in usb:*) printf '%s\n' "$LPI" | grep -qxF "$uri" || st=disconnected;; esac; fi
      [ $n -gt 0 ] && printf ','; n=$((n+1))
      printf '{"name":"%s","type":"%s","ip":"%s","mac":"%s","default":%s,"state":"%s"}' "$(js "$name")" "$t" "$(js "$ip")" "$(js "$mac")" "$d" "$st"
    done; printf ']'; }
}
# сканеры через SANE (scanimage -L): «device `epson2:net:192.168.0.50' is a Epson …» / «… libusb:001:005 …»
scanners() {
  command -v scanimage >/dev/null 2>&1 || { printf '[]'; return; }
  (timeout 25 scanimage -L 2>/dev/null || scanimage -L 2>/dev/null) | sed -n "s/^device \`\([^']*\)' is a \(.*\)$/\1\t\2/p" | {
    n=0; printf '['
    while IFS='	' read -r dev name; do
      t=other; ip=""; mac=""
      case "$dev" in *usb*|*libusb*) t=usb;; *net*|*airscan*|*escl*|*://*|*[0-9].[0-9]*.[0-9]*.[0-9]*) t=network;; esac
      ip=$(printf '%s %s' "$dev" "$name" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
      name=$(printf '%s' "$name" | sed 's/ *ip=[0-9.]*$//')
      [ -n "$ip" ] && mac=$(arp_mac "$ip")
      [ $n -gt 0 ] && printf ','; n=$((n+1))
      printf '{"name":"%s","type":"%s","ip":"%s","mac":"%s","default":false,"state":"ok"}' "$(js "$name")" "$t" "$(js "$ip")" "$(js "$mac")"
    done; printf ']'; }
}
# антивирус: известные службы/процессы (вкл = служба работает); macOS — ещё встроенный XProtect
antivirus() {
  n=0; printf '['
  add() { [ $n -gt 0 ] && printf ','; n=$((n+1)); printf '{"name":"%s","enabled":%s,"uptodate":null}' "$1" "$2"; }
  if [ "$(uname -s)" = Darwin ]; then
    for p in "Kaspersky:kav" "ESET:esets_daemon" "Sophos:SophosScanD" "Avast:com.avast.daemon" "Malwarebytes:RTProtectionDaemon" "Dr.Web:drweb" "Bitdefender:BDLDaemon"; do
      nm=${p%%:*}; pr=${p#*:}; if ls /Applications 2>/dev/null | grep -qi "$nm"; then if pgrep -if "$pr" >/dev/null 2>&1; then add "$nm" true; else add "$nm" false; fi; fi
    done
    [ -d /Library/Apple/System/Library/CoreServices/XProtect.bundle ] && add "XProtect (встроенный)" true
  else
    for p in "kesl:Kaspersky Endpoint Security" "klnagent64:Kaspersky Network Agent" "drweb-configd:Dr.Web" "eea:ESET Endpoint Antivirus" "esets:ESET" "clamav-daemon:ClamAV" "clamd:ClamAV" "sophos-spl:Sophos" "falcon-sensor:CrowdStrike Falcon" "mdatp:Microsoft Defender"; do
      un=${p%%:*}; nm=${p#*:}
      if systemctl list-unit-files "$un.service" 2>/dev/null | grep -q "^$un"; then
        if systemctl is-active --quiet "$un"; then add "$nm" true; else add "$nm" false; fi
      fi
    done
  fi
  printf ']'
}
if [ "$(uname -s)" = Darwin ]; then
  RD=/Applications/RustDesk.app/Contents/MacOS/RustDesk
  [ -n "$ID" ] || ID=$(HOME=/var/root "$RD" --get-id 2>/dev/null | tr -dc 0-9)
  [ -n "$ID" ] || ID=$("$RD" --get-id 2>/dev/null | tr -dc 0-9)
  CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null); RAM=$(sysctl -n hw.memsize 2>/dev/null)
  CORES=$(sysctl -n hw.physicalcpu 2>/dev/null); THR=$(sysctl -n hw.logicalcpu 2>/dev/null)
  RTYPE=$(system_profiler SPMemoryDataType 2>/dev/null | awk -F': ' '/^ *Type:/{print $2}' | grep -v -i 'empty' | sort -u | paste -sd/ -)
  SPD_DISP=$(system_profiler SPDisplaysDataType 2>/dev/null)
  GPU=$(printf '%s\n' "$SPD_DISP" | awk -F': ' '/Chipset Model:/{printf "%s%s", (n++?"; ":""), $2}')
  # VRAM только у дискретных видеокарт («VRAM (Total): 4 GB»); у Apple Silicon память общая — не показываем
  GMEM=$(printf '%s\n' "$SPD_DISP" | awk -F': ' '/Chipset Model:/{if(n++)printf "; "} /VRAM \((Total|Dynamic, Max)\):/{split($2,a," "); v=a[1]*(a[2]=="GB"?1073741824:1048576); printf "%.0f", v}')
  BV=Apple; BN=$(sysctl -n hw.model 2>/dev/null)
  SPBT=$(system_profiler SPBluetoothDataType 2>/dev/null)
  if [ -n "$SPBT" ]; then BTN=$(printf '%s\n' "$SPBT" | awk -F': ' '/Chipset:/{print $2; exit}'); BTN=${BTN:-Bluetooth}
    case "$(printf '%s\n' "$SPBT" | awk -F': ' '/State:/{print $2; exit}')" in On*) BTS=ok;; Off*) BTS=disabled;; *) BTS=ok;; esac
  else BTS=none; fi
  IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}'); IF=${IF:-en0}
  LIP=$(ipconfig getifaddr "$IF" 2>/dev/null); MAC=$(ifconfig "$IF" 2>/dev/null | awk '/ether /{print $2; exit}')
  NICN=$(networksetup -listallhardwareports 2>/dev/null | awk -v d="$IF" '/Hardware Port:/{p=substr($0,16)} $0=="Device: "d{print p; exit}')
  case "$NICN" in *Wi-Fi*|*AirPort*|*Wireless*) NT=wifi;; "") NT="";; *) NT=ethernet;; esac
  if [ "$NT" = ethernet ]; then
    SPD=$(ifconfig "$IF" 2>/dev/null | sed -n 's/.*media:.*(\([0-9]*\)\(G*\)base.*/\1\2/p' | head -1)
    case "$SPD" in *G) SPD=$(( ${SPD%G} * 1000 ));; esac
  fi
  PS=$(diskutil info / 2>/dev/null | awk -F': *' '/APFS Physical Store/{print $2; exit}' | sed 's/s[0-9]*$//')
  D=${PS:-disk0}; I=$(diskutil info "$D" 2>/dev/null)
  T=$(printf '%s\n' "$I" | awk -F': *' '/Solid State/{print ($2 ~ /Yes/) ? "SSD" : "HDD"}')
  P=$(printf '%s\n' "$I" | awk -F': *' '/Protocol/{print $2}')
  S=$(printf '%s\n' "$I" | awk -F': *' '/Disk Size/{split($2,a," "); printf "%.0f GB", a[1]; exit}')
  M=$(printf '%s\n' "$I" | awk -F': *' '/Media Name/{print $2; exit}')
  case "$P" in *PCI*|*Fabric*|*NVM*) T="NVMe ${T:-SSD}";; esac
  [ -n "$S" ] && DISK="${T:-Disk} $S ($M)"
  USERS=$(dscl . list /Users UniqueID 2>/dev/null | awk '$2>=500 && $1 !~ /^_/{printf "%s%s", (n++?"; ":""), $1}')
  LOGGED=$(stat -f %Su /dev/console 2>/dev/null)
  PLAT=mac
else
  RD=$(command -v rustdesk || echo /usr/bin/rustdesk)
  [ -n "$ID" ] || ID=$("$RD" --get-id 2>/dev/null | tr -dc 0-9)
  CPU=$(awk -F': *' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
  [ -n "$CPU" ] || CPU=$(lscpu 2>/dev/null | awk -F': *' '/Model name/{print $2; exit}')
  THR=$(nproc --all 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)
  CORES=$(lscpu -p=core,socket 2>/dev/null | grep -v '^#' | sort -u | wc -l | tr -d ' '); [ "${CORES:-0}" -gt 0 ] 2>/dev/null || CORES=""
  GPU=$(lspci 2>/dev/null | grep -iE 'VGA|3D controller|Display controller' | sed 's/^[^ ]* [^:]*: //; s/ (rev [0-9a-f]*)$//' | awk '{printf "%s%s", (n++?"; ":""), $0}')
  # видеопамять дискретных карт: AMD — mem_info_vram_total, NVIDIA — nvidia-smi (МиБ); встроенная графика — без объёма
  GMEM=$( { for f in /sys/class/drm/card[0-9]/device/mem_info_vram_total; do [ -r "$f" ] && cat "$f"; done
           command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | awk '{printf "%.0f\n", $1*1048576}'; } 2>/dev/null \
         | awk '$1>1073741824{printf "%s%s", (n++?"; ":""), $1}')
  BV=$(cat /sys/class/dmi/id/board_vendor 2>/dev/null); BN=$(cat /sys/class/dmi/id/board_name 2>/dev/null)
  # Bluetooth: адаптер = /sys/class/bluetooth/hciN; выключен = rfkill soft/hard block
  H0=$(ls -d /sys/class/bluetooth/hci* 2>/dev/null | head -1)
  if [ -n "$H0" ]; then
    BTN=$(basename "$H0"); V=$(cat "$H0/device/../manufacturer" 2>/dev/null; cat "$H0/device/../product" 2>/dev/null); [ -n "$V" ] && BTN=$(printf '%s' "$V" | tr '\n' ' ' | sed 's/ *$//')
    BTS=ok; for rf in /sys/class/rfkill/rfkill*; do [ "$(cat "$rf/type" 2>/dev/null)" = bluetooth ] || continue
      [ "$(cat "$rf/soft" 2>/dev/null)" = 1 ] || [ "$(cat "$rf/hard" 2>/dev/null)" = 1 ] && BTS=disabled; done
  else BTS=none; fi
  if command -v dmidecode >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    RAM=$(dmidecode -t 17 2>/dev/null | awk '/^\tSize: [0-9]+ (MB|GB)/{s+=($3=="GB")?$2*1024:$2} END{if(s>0) printf "%.0f", s*1048576}')
    RTYPE=$(dmidecode -t 17 2>/dev/null | awk -F': ' '/^\tType: /{print $2}' | grep -vE '^(Unknown|Other|RAM)$' | sort -u | paste -sd/ -)
  fi
  [ -n "$RAM" ] || RAM=$(awk '/^MemTotal:/{g=$2/1048576; r=int(g/2); if (r*2<g) r++; printf "%.0f", r*2*1073741824}' /proc/meminfo 2>/dev/null)
  DEV=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
  LIP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  if [ -n "$DEV" ]; then
    MAC=$(cat "/sys/class/net/$DEV/address" 2>/dev/null)
    if [ -d "/sys/class/net/$DEV/wireless" ] || [ -d "/sys/class/net/$DEV/phy80211" ]; then NT=wifi
    elif [ -e "/sys/class/net/$DEV/device" ]; then NT=ethernet
      SPD=$(cat "/sys/class/net/$DEV/speed" 2>/dev/null); [ "${SPD:-0}" -gt 0 ] 2>/dev/null || SPD=""
    else NT=other; fi
    PCI=$(basename "$(readlink -f "/sys/class/net/$DEV/device" 2>/dev/null)" 2>/dev/null)
    NICN=$(lspci -s "$PCI" 2>/dev/null | sed 's/^[^ ]* [^:]*: //; s/ (rev [0-9a-f]*)$//' | head -1)
    [ -n "$NICN" ] || NICN="$DEV ($(basename "$(readlink "/sys/class/net/$DEV/device/driver" 2>/dev/null)" 2>/dev/null))"
  fi
  SRC=$(findmnt -no SOURCE / 2>/dev/null)
  SD=$(lsblk -nso NAME,TYPE "$SRC" 2>/dev/null | awk '$2=="disk"{gsub(/^[^a-zA-Z0-9]+/,"",$1); print $1; exit}')
  [ -n "$SD" ] && DISK=$(lsblk -dbno ROTA,TRAN,SIZE,MODEL "/dev/$SD" 2>/dev/null | awk -v n="$SD" '{t=($2=="nvme"||n ~ /^nvme/)?"NVMe SSD":($1=="1"?"HDD":"SSD"); if($2=="usb")t="USB "t; m="";for(i=4;i<=NF;i++)m=m (i>4?" ":"") $i; printf "%s %d GB (%s)", t, $3/1e9+0.5, (m!=""?m:n); exit}')
  USERS=$(awk -F: '$3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/{printf "%s%s", (n++?"; ":""), $1}' /etc/passwd 2>/dev/null)
  LOGGED=$(who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ *$//; s/ /, /g')
  PLAT=linux
fi
[ -n "$ID" ] || { say "Не удалось узнать ID RustDesk (RustDesk не установлен? запустите через sudo)"; exit 1; }
# самообновление копии для расписания (исправления доходят до ПК без повторного запуска команды)
if [ -n "${RD_HW_TASK:-}" ] && [ "$(id -u)" = 0 ]; then
  for SELF in "/usr/local/lib/rustdesk-neth/hw.sh" "/Library/Application Support/RustDeskNETH/hw.sh"; do
    [ -f "$SELF" ] || continue
    get "$BASE/hw.sh" > "$SELF.new" 2>/dev/null && head -1 "$SELF.new" | grep -q '^#!/bin/sh' && [ "$(wc -c < "$SELF.new")" -gt 2000 ] && mv "$SELF.new" "$SELF" && chmod 700 "$SELF" || rm -f "$SELF.new"
  done
fi
PRJ=$(printers); SCJ=$(scanners); AVJ=$(antivirus); SWJ=$(software)
J=$(printf '{%s,"id":"%s","cpu":"%s","gpu":"%s","ram":"%s","disk":"%s","nic_type":"%s","nic_mbps":"%s","nic_name":"%s","mac":"%s","local_ip":"%s","users":"%s","logged_user":"%s","printers":"%s","scanners":"%s","antivirus":"%s","software":"%s","gpu_mem":"%s","board_vendor":"%s","board_name":"%s","cpu_cores":"%s","cpu_threads":"%s","ram_type":"%s","bt_name":"%s","bt_state":"%s"}' \
  "$(auth)" "$ID" "$(js "$CPU")" "$(js "$GPU")" "$(js "$RAM")" "$(js "$DISK")" "$NT" "$(js "$SPD")" "$(js "$NICN")" "$(js "$MAC")" "$(js "$LIP")" "$(js "$USERS")" "$(js "$LOGGED")" "$(js "$PRJ")" "$(js "$SCJ")" "$(js "$AVJ")" "$(js "$SWJ")" "$(js "$GMEM")" "$(js "$BV")" "$(js "$BN")" "$(js "$CORES")" "$(js "$THR")" "$(js "$RTYPE")" "$(js "$BTN")" "$BTS")
post() { if command -v curl >/dev/null 2>&1; then curl -fsS -m 20 -H 'Content-Type: application/json' -d "$J" "$1/api/rds/hwinfo"; else wget -qO- -T 20 --header='Content-Type: application/json' --post-data="$J" "$1/api/rds/hwinfo"; fi; }
if HR=$(post "$API" 2>/dev/null) || HR=$(post "$BASE" 2>/dev/null); then
  akey_save "$HR"
  say "Данные обновлены: ID $ID | $CPU | $GPU | ОЗУ $(( ${RAM:-0} / 1073741824 )) ГБ | $DISK | ${NT:-?} ${SPD:+$SPD Мбит/с} | MAC $MAC | IP $LIP"
else say "Сервер не ответил"; exit 1; fi
# автообновление (только от root и не из самого расписания)
[ -z "${RD_HW_TASK:-}" ] || exit 0
if [ "$(id -u)" != 0 ]; then say "Автообновление НЕ установлено: запустите команду через sudo."; exit 0; fi
if [ "$PLAT" = mac ]; then
  DIR="/Library/Application Support/RustDeskNETH"; mkdir -p "$DIR"
  get "$BASE/hw.sh" > "$DIR/hw.sh.tmp" && mv "$DIR/hw.sh.tmp" "$DIR/hw.sh" && chmod 700 "$DIR/hw.sh"
  PL=/Library/LaunchDaemons/net.neth.rustdesk-hw.plist
  cat > "$PL" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>net.neth.rustdesk-hw</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>$DIR/hw.sh</string></array>
<key>EnvironmentVariables</key><dict><key>RD_HW_TASK</key><string>1</string></dict>
<key>RunAtLoad</key><true/><key>StartInterval</key><integer>43200</integer>
</dict></plist>
PLIST
  launchctl unload "$PL" >/dev/null 2>&1; launchctl load -w "$PL" >/dev/null 2>&1 && say "Автообновление установлено: при загрузке и каждые 12 ч (LaunchDaemon net.neth.rustdesk-hw)."
  PP=/Library/LaunchDaemons/net.neth.rustdesk-poll.plist
  sed -e 's/net.neth.rustdesk-hw/net.neth.rustdesk-poll/; s|<key>RD_HW_TASK</key><string>1</string>|<key>RD_HW_TASK</key><string>1</string><key>RD_POLL</key><string>1</string>|; s|<integer>43200</integer>|<integer>60</integer>|' "$PL" > "$PP"
  launchctl unload "$PP" >/dev/null 2>&1; launchctl load -w "$PP" >/dev/null 2>&1 && say "Команды из панели (обновление, выключение, перезагрузка): проверка каждую минуту (net.neth.rustdesk-poll)."
else
  DIR=/usr/local/lib/rustdesk-neth; mkdir -p "$DIR"
  get "$BASE/hw.sh" > "$DIR/hw.sh.tmp" && mv "$DIR/hw.sh.tmp" "$DIR/hw.sh" && chmod 700 "$DIR/hw.sh"
  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    printf '[Unit]\nDescription=RustDesk NETH: hardware info to the panel\nAfter=network-online.target\n[Service]\nType=oneshot\nEnvironment=RD_HW_TASK=1\nExecStart=/bin/sh %s/hw.sh\n' "$DIR" > /etc/systemd/system/rustdesk-neth-hw.service
    printf '[Unit]\nDescription=RustDesk NETH: hardware info at boot and every 12 h\n[Timer]\nOnBootSec=3min\nOnUnitActiveSec=12h\nPersistent=true\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/rustdesk-neth-hw.timer
    systemctl daemon-reload && systemctl enable --now rustdesk-neth-hw.timer >/dev/null 2>&1 && say "Автообновление установлено: при загрузке и каждые 12 ч (таймер rustdesk-neth-hw)."
    printf '[Unit]\nDescription=RustDesk NETH: commands from the panel\nAfter=network-online.target\n[Service]\nType=oneshot\nEnvironment=RD_HW_TASK=1 RD_POLL=1\nExecStart=/bin/sh %s/hw.sh\n' "$DIR" > /etc/systemd/system/rustdesk-neth-poll.service
    printf '[Unit]\nDescription=RustDesk NETH: check panel commands every minute\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/rustdesk-neth-poll.timer
    systemctl daemon-reload && systemctl enable --now rustdesk-neth-poll.timer >/dev/null 2>&1 && say "Команды из панели (обновление, выключение, перезагрузка): проверка каждую минуту (таймер rustdesk-neth-poll)."
  else
    printf '#!/bin/sh\nRD_HW_TASK=1 /bin/sh %s/hw.sh\n' "$DIR" > /etc/cron.daily/rustdesk-neth-hw && chmod 755 /etc/cron.daily/rustdesk-neth-hw && say "Автообновление установлено: раз в сутки (cron.daily)."
  fi
fi
