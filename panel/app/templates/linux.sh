#!/bin/sh
# RustDesk NETH для Linux — один скрипт для всех дистрибутивов:
#   curl -fsSL __BASE__/linux.sh__Q__ | sudo sh        (или: wget -qO- __BASE__/linux.sh__Q__ | sudo sh)
# Debian / Ubuntu / Mint / Astra Linux ........ .deb  (apt)
# RHEL / CentOS / Rocky / Alma / Fedora / РЕД ОС / ROSA / Oracle .. .rpm (dnf/yum)
# openSUSE / SLES ............................. .rpm для SUSE (zypper)
# ALT Linux ................................... .rpm (apt-get + rpm)
# Arch / Manjaro / EndeavourOS ................ .pkg.tar.zst (pacman)
# Готовый пакет можно подложить заранее: RD_PKG=/путь/к/пакету (без скачивания).
[ "$(id -u)" = 0 ] || { echo "Запустите от root: ... | sudo sh"; exit 1; }
BASE='__BASE__'
has() { command -v "$1" >/dev/null 2>&1; }
get() { if has curl; then curl -fsSL -m 15 "$1"; elif has wget; then wget -qO- -T 15 "$1"; fi; }
dl()  { if has curl; then curl -fL --retry 2 -m 900 -o "$2" "$1"; elif has wget; then wget -q -T 60 -O "$2" "$1"; else return 1; fi; }
die() { echo "ОШИБКА: $*"; exit 1; }

[ -r /etc/os-release ] && . /etc/os-release
F=""
for w in $(echo "${ID:-} ${ID_LIKE:-}" | tr 'A-Z' 'a-z' | tr -d '"'); do
  case "$w" in
    altlinux|alt) F=alt; break;;
    debian|ubuntu|astra|linuxmint|raspbian|kali|devuan) F=deb; break;;
    opensuse*|suse|sles|sled) F=suse; break;;
    arch|archarm|manjaro|endeavouros|garuda|artix) F=arch; break;;
    rhel|centos|fedora|rocky|almalinux|ol|redos|rosa|openmandriva|mageia|amzn|msvsphere) F=rpm; break;;
  esac
done
if [ -z "$F" ]; then
  if has apt-get && has dpkg; then F=deb; elif has pacman; then F=arch; elif has zypper; then F=suse; elif has dnf || has yum; then F=rpm; fi
fi
[ -n "$F" ] || die "не удалось определить дистрибутив (${PRETTY_NAME:-неизвестный}). Поддерживаются семейства Debian, RHEL/Fedora, SUSE, ALT, Arch."
case "$(uname -m)" in
  x86_64|amd64) A=x86_64;; aarch64|arm64) A=aarch64;; armv7*|armhf) A=armv7;;
  *) die "архитектура $(uname -m) не поддерживается RustDesk";;
esac
case "$F-$A" in
  deb-x86_64|deb-aarch64) RX="rustdesk-[0-9.]+-$A\\.deb"; L=rustdesk-latest-$A.deb;;
  deb-armv7)              RX="rustdesk-[0-9.]+-armv7-sciter\\.deb"; L=rustdesk-latest-armv7-sciter.deb;;
  rpm-x86_64|rpm-aarch64|alt-x86_64|alt-aarch64) RX="rustdesk-[0-9.]+-0\\.$A\\.rpm"; L=rustdesk-latest-$A.rpm;;
  suse-x86_64|suse-aarch64) RX="rustdesk-[0-9.]+-0\\.$A-suse\\.rpm"; L=rustdesk-latest-$A-suse.rpm;;
  arch-x86_64)            RX="rustdesk-[0-9.]+-0-x86_64\\.pkg\\.tar\\.zst"; L=rustdesk-latest-x86_64.pkg.tar.zst;;
  *) die "для $F на $A официального пакета RustDesk нет";;
esac
echo "Система: ${PRETTY_NAME:-$ID} ($A) → пакет $F"
OLD="RustDesk 1.5 работает на Debian 11+, Ubuntu 20.04+, Astra 1.7+, RHEL/CentOS/Rocky/Alma 8+, РЕД ОС 7.3+, ALT p10+. Для этой системы обратитесь к администратору."
G=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
if [ -n "$G" ] && [ "$(printf '%s\n2.28\n' "$G" | sort -t. -k1,1n -k2,2n | head -1)" != 2.28 ]; then die "слишком старая система (glibc $G). $OLD"; fi
[ "$F" = deb ] && [ "${ID:-}" = debian ] && [ "${VERSION_ID%%.*}" -lt 11 ] 2>/dev/null && die "Debian ${VERSION_ID} слишком старый. $OLD"
has systemctl || echo "ВНИМАНИЕ: нет systemd — служба RustDesk сама не запустится"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
case "$L" in *.deb) P=$T/rustdesk.deb;; *.rpm) P=$T/rustdesk.rpm;; *) P=$T/rustdesk.pkg.tar.zst;; esac
if [ -n "${RD_PKG:-}" ] && [ -f "$RD_PKG" ]; then cp "$RD_PKG" "$P"
else
  GH=$(get https://api.github.com/repos/rustdesk/rustdesk/releases/latest 2>/dev/null | grep -oE "https://[^\"]*/$RX" | head -1)
  if [ -z "$GH" ] || ! dl "$GH" "$P"; then
    echo "GitHub недоступен, качаю с сервера..."
    dl "$BASE/dl/official/$L" "$P" || die "не удалось скачать RustDesk"
  fi
fi

case "$F" in
  deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y "$P" || { dpkg -i "$P"; apt-get -f install -y; } ;;
  rpm)
    if has dnf; then dnf install -y "$P"; else yum install -y "$P"; fi ;;
  suse)
    zypper --non-interactive --no-gpg-checks install --allow-unsigned-rpm "$P" ;;
  alt)
    # имена зависимостей в rpm от Fedora, в ALT пакеты называются иначе — ставим аналоги, затем сам rpm
    apt-get update -qq >/dev/null 2>&1
    for p in libgtk+3 libalsa libXfixes libXtst libxcb libva gst-plugins-base1.0 gst-plugins-good1.0 pipewire xdotool; do
      apt-get install -y -qq "$p" >/dev/null 2>&1 || true
    done
    rpm -Uvh --nodeps --replacepkgs "$P" ;;
  arch)
    pacman -Sy --noconfirm --needed gtk3 xdotool libxcb libxfixes alsa-lib libva gst-plugins-base gst-plugin-pipewire >/dev/null 2>&1 || true
    pacman -U --noconfirm "$P" ;;
esac
# звук (libpulse-simple) RustDesk грузит при запуске, но в зависимостях пакета его нет
if ! ldconfig -p 2>/dev/null | grep -q 'libpulse-simple\.so\.0'; then
  case "$F" in
    deb) apt-get install -y -qq libpulse0 ;; rpm) if has dnf; then dnf install -y -q pulseaudio-libs; else yum install -y -q pulseaudio-libs; fi ;;
    suse) zypper --non-interactive install libpulse0 ;; alt) apt-get install -y -qq libpulseaudio ;; arch) pacman -S --noconfirm --needed libpulse ;;
  esac >/dev/null 2>&1
fi
RD=/usr/bin/rustdesk; [ -x "$RD" ] || RD=/usr/share/rustdesk/rustdesk
[ -x "$RD" ] || die "RustDesk не установился — пришлите вывод выше администратору"
M=$(ldd /usr/share/rustdesk/rustdesk 2>/dev/null | grep 'not found')
[ -z "$M" ] || echo "ВНИМАНИЕ: не хватает библиотек: $M"
if has systemctl; then
  [ -f /etc/systemd/system/rustdesk.service ] || [ -f /usr/lib/systemd/system/rustdesk.service ] || cp /usr/share/rustdesk/files/rustdesk.service /etc/systemd/system/ 2>/dev/null
  systemctl daemon-reload 2>/dev/null; systemctl enable --now rustdesk 2>/dev/null
fi
trap - EXIT; rm -rf "$T"
# RD_UPDATE_ONLY=1 — обновление по кнопке из панели: только пакет, настройки/пароль/регистрацию не трогаем
if [ -n "${RD_UPDATE_ONLY:-}" ]; then echo "RustDesk обновлён: $("$RD" --version 2>/dev/null | head -1)"; exit 0; fi
# ---- настройка
