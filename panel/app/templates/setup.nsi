Unicode true
; RustDesk NETH — установщик для Windows 7 / 8.1 / 10 / 11 (x64, x86, ARM64).
; Сам ничего не ставит: по шагам запускает setup.ps1 (скачать → установить → настроить → зарегистрировать).
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinMessages.nsh"

Name "RustDesk"
Caption "${CAPTION}"
OutFile "${OUT}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "RustDesk · удалённая помощь"
ShowInstDetails hide
VIProductVersion "${VIVER}"
VIAddVersionKey /LANG=0 "ProductName" "RustDesk Setup"
VIAddVersionKey /LANG=0 "FileDescription" "RustDesk Setup"
VIAddVersionKey /LANG=0 "FileVersion" "${RDVER}"
VIAddVersionKey /LANG=0 "LegalCopyright" "RustDesk is AGPL-3.0; this installer only configures it"

!define MUI_ICON "${ICON}"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${HDR}"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${WEL}"
!define MUI_ABORTWARNING
!define MUI_ABORTWARNING_TEXT "Прервать установку RustDesk?"

!define MUI_WELCOMEPAGE_TITLE "Удалённая помощь RustDesk"
!define MUI_WELCOMEPAGE_TEXT "Будет установлен официальный RustDesk и подключён к серверу поддержки.$\r$\n$\r$\nЭто займёт 1–3 минуты, нужен интернет. Если RustDesk уже запущен, он будет закрыт и переустановлен.$\r$\n$\r$\nВ конце появится ваш ID — сообщите его специалисту.$\r$\n$\r$\nНажмите «Установить»."
!define MUI_PAGE_CUSTOMFUNCTION_SHOW WelcomeShow
!insertmacro MUI_PAGE_WELCOME

!define MUI_PAGE_HEADER_TEXT "Установка RustDesk"
!define MUI_PAGE_HEADER_SUBTEXT "Подождите, всё делается автоматически."
!define MUI_INSTFILESPAGE_FINISHHEADER_TEXT "Готово"
!define MUI_INSTFILESPAGE_FINISHHEADER_SUBTEXT "RustDesk установлен."
!define MUI_INSTFILESPAGE_ABORTHEADER_TEXT "Установка не завершена"
!define MUI_INSTFILESPAGE_ABORTHEADER_SUBTEXT "Нажмите «Показать детали», сделайте снимок экрана и отправьте специалисту."
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

Var PS
Var Line1
Var Line2
Var Line3
Var Step

Function WelcomeShow
  GetDlgItem $0 $HWNDPARENT 1
  SendMessage $0 ${WM_SETTEXT} 0 "STR:Установить"
FunctionEnd

; один шаг: русская строка статуса, вывод PowerShell — только в «деталях»
!macro Step NAME TEXT
  StrCpy $Step "${TEXT}"
  SetDetailsPrint both
  DetailPrint "${TEXT}"
  SetDetailsPrint listonly
  nsExec::ExecToLog '"$PS" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\setup.ps1" -Stage ${NAME} -Dir "$PLUGINSDIR"'
  Pop $0
  SetDetailsPrint both
  ${If} $0 != 0
    Goto failed
  ${EndIf}
!macroend

Section
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "/oname=setup.ps1" "${PS1}"
  StrCpy $PS "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  ${If} ${RunningX64}
    ${If} ${FileExists} "$WINDIR\sysnative\WindowsPowerShell\v1.0\powershell.exe"
      StrCpy $PS "$WINDIR\sysnative\WindowsPowerShell\v1.0\powershell.exe"
    ${EndIf}
  ${EndIf}
  ${IfNot} ${FileExists} "$PS"
    MessageBox MB_ICONSTOP "В этой Windows нет PowerShell — установка невозможна.$\r$\nОбратитесь к специалисту."
    Quit
  ${EndIf}

  !insertmacro Step "prep"     "Закрываю запущенный RustDesk…"
  !insertmacro Step "download" "Скачиваю RustDesk…"
  !insertmacro Step "install"  "Устанавливаю RustDesk…"
  !insertmacro Step "config"   "Подключаю к серверу и задаю пароль…"
  !insertmacro Step "register" "Сообщаю данные специалисту…"

  ClearErrors
  FileOpen $1 "$PLUGINSDIR\result.txt" r
  FileRead $1 $Line1
  FileRead $1 $Line2
  FileRead $1 $Line3
  FileClose $1
  Push $Line1
  Call Trim
  Pop $Line1
  Push $Line2
  Call Trim
  Pop $Line2
  Push $Line3
  Call Trim
  Pop $Line3
  DetailPrint "Готово. Ваш ID: $Line1"
  ${If} $Line2 == "ok"
    MessageBox MB_ICONINFORMATION|MB_OK|MB_TOPMOST|MB_SETFOREGROUND "RustDesk установлен и подключён к серверу.$\r$\n$\r$\nВаш ID: $Line1$\r$\n$\r$\nСообщите этот номер специалисту."
  ${Else}
    StrCpy $2 $Line2 "" 6
    ${If} $2 != ""
      StrCpy $2 "$\r$\nПароль: $2"
    ${EndIf}
    MessageBox MB_ICONEXCLAMATION|MB_OK|MB_TOPMOST|MB_SETFOREGROUND "RustDesk установлен, но сервер не ответил.$\r$\nПерешлите специалисту:$\r$\n$\r$\nID: $Line1$2"
  ${EndIf}
  ${If} $Line3 != ""
  ${AndIf} ${FileExists} "$Line3"
    ; через explorer — RustDesk запускается от обычного пользователя, а не от администратора (как сам установщик).
    ; Иначе браузер не может передать ему ссылку rustdesk:// (Windows блокирует сообщения в окно с правами админа).
    Exec '"$WINDIR\explorer.exe" "$Line3"'
  ${EndIf}
  Quit

failed:
  SetDetailsView show
  MessageBox MB_ICONSTOP|MB_OK|MB_TOPMOST|MB_SETFOREGROUND "Не удалось выполнить шаг: $Step (код $0).$\r$\n$\r$\nСделайте снимок экрана окна установки и отправьте специалисту."
  Abort
SectionEnd

Function Trim
  Exch $R0
  Push $R1
  loop:
    StrCpy $R1 $R0 1 -1
    ${If} $R1 == "$\r"
    ${OrIf} $R1 == "$\n"
    ${OrIf} $R1 == " "
      StrCpy $R0 $R0 -1
      Goto loop
    ${EndIf}
  Pop $R1
  Exch $R0
FunctionEnd
