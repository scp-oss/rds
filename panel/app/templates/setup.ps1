param([string]$Stage = 'all', [string]$Dir = $env:TEMP)
# RustDesk NETH for Windows 7 / 8.1 / 10 / 11 (x64, x86, ARM64): download, install, server config, password, register.
# ASCII only (PS 5.1 reads scripts as ANSI). PowerShell 2.0 compatible: no Invoke-WebRequest / Invoke-RestMethod / ConvertTo-Json.
# Stages are run one by one by the NSIS installer: prep, download, install, config, register (state is kept in $Dir).
$ErrorActionPreference = 'Continue'
$CFG    = '__CFG__'
$API    = '__API__'
$TOKEN  = '__TOKEN__'
$MASTER = __MASTER__
$BASE   = '__BASE__'
$LOGIN_TOKEN = '__LOGIN_TOKEN__'
$LOGIN_USER  = '__LOGIN_USER__'

# TLS 1.2 for .NET (works where .NET 4.5+ or the Win7 TLS update is present; otherwise WinInet fallback below)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]([int]3072 -bor 768 -bor 192) } catch {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls } catch {} }

function Log([string]$m) { [Console]::Out.WriteLine($m) }   # not Write-Output: functions below return exit codes
$Installer = Join-Path $Dir 'rustdesk-setup.exe'
$StateFile = Join-Path $Dir 'state.txt'
$Result    = Join-Path $Dir 'result.txt'

function Save-State([string]$k, [string]$v) { Add-Content -Path $StateFile -Value ($k + '=' + $v) -Encoding Ascii }
function Get-State([string]$k) {
    if (-not (Test-Path $StateFile)) { return '' }
    $r = ''
    foreach ($l in (Get-Content $StateFile)) { if ($l.StartsWith($k + '=')) { $r = $l.Substring($k.Length + 1) } }
    return $r
}
function JStr([string]$s) {
    if ($s -eq $null) { $s = '' }
    $o = New-Object Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        $n = [int]$c
        if ($c -eq '"' -or $c -eq '\') { [void]$o.Append('\').Append($c) }
        elseif ($n -lt 32 -or $n -gt 126) { [void]$o.Append('\u' + $n.ToString('x4')) }
        else { [void]$o.Append($c) }
    }
    return '"' + $o.ToString() + '"'
}

# ---- HTTP: .NET WebClient first, then WinInet (MSXML2.XMLHTTP) which follows the system/IE TLS settings
function Http-Get([string]$url, [string]$file) {
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', 'rds-setup')
        if ($file) { $wc.DownloadFile($url, $file); return 'ok' } else { return $wc.DownloadString($url) }
    } catch { Log ("  .NET: " + $_.Exception.Message) }
    try {
        $x = New-Object -ComObject 'Msxml2.XMLHTTP'
        $x.open('GET', $url, $false); $x.setRequestHeader('User-Agent', 'rds-setup'); $x.send()
        if ($x.status -ne 200) { throw ('HTTP ' + $x.status) }
        if ($file) { [IO.File]::WriteAllBytes($file, [byte[]]$x.responseBody); return 'ok' } else { return [string]$x.responseText }
    } catch { Log ("  WinInet: " + $_.Exception.Message) }
    return $null
}
function Http-Post([string]$url, [string]$json) {
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('Content-Type', 'application/json; charset=utf-8'); $wc.Encoding = [Text.Encoding]::UTF8
        [void]$wc.UploadString($url, 'POST', $json); return $true
    } catch { Log ("  .NET: " + $_.Exception.Message) }
    try {
        $x = New-Object -ComObject 'Msxml2.XMLHTTP'
        $x.open('POST', $url, $false); $x.setRequestHeader('Content-Type', 'application/json; charset=utf-8'); $x.send($json)
        if ($x.status -ge 200 -and $x.status -lt 300) { return $true }
        Log ('  WinInet: HTTP ' + $x.status)
    } catch { Log ("  WinInet: " + $_.Exception.Message) }
    return $false
}
__HWPS__
function Sha256([string]$f) {
    $s = [IO.File]::OpenRead($f)
    try { $h = [Security.Cryptography.SHA256]::Create().ComputeHash($s) } finally { $s.Close() }
    return (-join ($h | ForEach-Object { $_.ToString('x2') }))
}

# ---- which RustDesk build fits this PC
function Get-Builds {
    $v = [Environment]::OSVersion.Version
    $cpu = $env:PROCESSOR_ARCHITEW6432; if (-not $cpu) { $cpu = $env:PROCESSOR_ARCHITECTURE }
    if ($v.Major -lt 10) { return @('x86-sciter') }              # Windows 7 / 8 / 8.1: Flutter build does not run there
    if ($cpu -eq 'ARM64') { return @('aarch64', 'x86_64') }      # native ARM build, x64 under emulation as fallback
    if ($cpu -eq 'AMD64') { return @('x86_64') }
    return @('x86-sciter')                                        # 32-bit Windows 10
}
function Find-Rd {
    $c = @()
    if ($env:ProgramW6432) { $c += (Join-Path $env:ProgramW6432 'RustDesk\rustdesk.exe') }
    $c += (Join-Path $env:ProgramFiles 'RustDesk\rustdesk.exe')
    if (${env:ProgramFiles(x86)}) { $c += (Join-Path ${env:ProgramFiles(x86)} 'RustDesk\rustdesk.exe') }
    foreach ($p in $c) { if (Test-Path $p) { return $p } }
    return ''
}

function Stage-Prep {
    # a running RustDesk (service, tray, open windows) blocks the silent install
    Log 'Stopping running RustDesk...'
    & sc.exe stop RustDesk 2>$null | Out-Null
    for ($i = 0; $i -lt 10; $i++) {
        & taskkill.exe /F /T /IM rustdesk.exe 2>$null | Out-Null
        Start-Sleep -Seconds 1
        if (-not (Get-Process rustdesk -ErrorAction SilentlyContinue)) { break }
    }
    if (Test-Path $StateFile) { Remove-Item $StateFile -Force }
    $v = [Environment]::OSVersion.Version
    Log ("Windows " + $v.ToString() + ", CPU " + $env:PROCESSOR_ARCHITECTURE + " " + $env:PROCESSOR_ARCHITEW6432 + ", PowerShell " + $PSVersionTable.PSVersion.ToString())
    return 0
}

function Stage-Download {
    $builds = Get-Builds
    Log ('Builds to try: ' + ($builds -join ', '))
    # SHA-256 of the files cached on our server: lets us accept a file even where Authenticode can't be checked (old Win7)
    $sums = @{}
    $t = Http-Get ($BASE + '/dl/official/SHA256SUMS') ''
    if ($t) { foreach ($l in ($t -split "`n")) { $p = $l.Trim() -split '\s+'; if ($p.Count -eq 2) { $sums[$p[0].ToLower()] = $p[1] } } }
    $rel = Http-Get 'https://api.github.com/repos/rustdesk/rustdesk/releases/latest' ''
    if (-not $rel) { Log 'GitHub API unavailable' }
    foreach ($b in $builds) {
        $local = 'rustdesk-latest-' + $b + '.exe'
        $urls = @()
        if ($rel) {
            $m = [regex]::Match($rel, '"browser_download_url"\s*:\s*"(https://[^"]+/rustdesk-[0-9.]+-' + [regex]::Escape($b) + '\.exe)"')
            if ($m.Success) { $urls += $m.Groups[1].Value }
        }
        $urls += ($BASE + '/dl/official/' + $local)
        foreach ($u in $urls) {
            Log ('Downloading ' + $u)
            if (Test-Path $Installer) { Remove-Item $Installer -Force }
            if (-not (Http-Get $u $Installer)) { continue }
            if (-not (Test-Path $Installer) -or (Get-Item $Installer).Length -lt 1000000) { Log '  file too small'; continue }
            $okSig = $false
            try { $sig = Get-AuthenticodeSignature $Installer; $okSig = ($sig.Status -eq 'Valid'); Log ('  signature: ' + $sig.Status) } catch {}
            $okSum = $false
            if ($sums.ContainsKey($local)) { $okSum = ((Sha256 $Installer) -eq $sums[$local]); Log ('  sha256 match: ' + $okSum) }
            if ($okSig -or $okSum) { Save-State 'build' $b; return 0 }
            Log '  REJECTED: neither a valid signature nor a known checksum'
        }
    }
    if (Test-Path $Installer) { Remove-Item $Installer -Force }
    Log 'Could not download RustDesk from GitHub or from the server'
    return 3
}

function Stage-Install {
    Log 'Installing RustDesk...'
    Start-Process -FilePath $Installer -ArgumentList '--silent-install'
    Start-Sleep -Seconds 10   # on reinstall the file already exists - let the installer finish
    $rd = ''
    for ($i = 0; $i -lt 90; $i++) { $rd = Find-Rd; if ($rd) { break }; Start-Sleep -Seconds 2 }
    if (-not $rd) { Log 'RustDesk not found in Program Files'; return 2 }
    Log ('Installed: ' + $rd)
    $svc = $null
    for ($i = 0; $i -lt 45; $i++) {
        $svc = Get-Service -Name 'RustDesk' -ErrorAction SilentlyContinue
        if ($svc -eq $null) { if ($i -lt 10) { Start-Sleep -Seconds 2; continue }; Start-Process -FilePath $rd -ArgumentList '--install-service'; Start-Sleep -Seconds 5; continue }
        if ($svc.Status -ne 'Running') { Start-Service 'RustDesk' -ErrorAction SilentlyContinue } else { break }
        Start-Sleep -Seconds 2
    }
    Start-Sleep -Seconds 3
    Save-State 'rd' $rd
    Remove-Item $Installer -Force -ErrorAction SilentlyContinue
    return 0
}

function Stage-Config {
    $rd = Get-State 'rd'; if (-not $rd) { $rd = Find-Rd }
    if (-not $rd) { Log 'RustDesk not installed'; return 2 }
    Log 'Applying server settings...'
    $rh = ([Uri]$API).Host
    for ($i = 0; $i -lt 20; $i++) {
        & $rd --config $CFG | Out-Null
        if (((& $rd --option custom-rendezvous-server | Out-String).Trim()) -eq $rh) { break }
        Start-Sleep -Seconds 2
    }
    # the service restarts after install - retry until RustDesk confirms
    $pw = ''
    if ($MASTER) {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'.ToCharArray()
        $bytes = New-Object byte[] 14
        (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
        $p = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
        for ($i = 0; $i -lt 20; $i++) {
            if ((& $rd --password $p | Out-String) -match 'Done') { $pw = $p; break }
            Start-Sleep -Seconds 2
        }
        if (-not $pw) { Log 'WARNING: permanent password was not applied' }
        $vm = 'use-both-passwords'
    } else { $vm = 'use-temporary-password' }
    for ($i = 0; $i -lt 20; $i++) {
        & $rd --option verification-method $vm | Out-Null
        if (((& $rd --option verification-method | Out-String).Trim()) -eq $vm) { break }
        Start-Sleep -Seconds 2
    }
    $id = ''
    for ($i = 0; $i -lt 30; $i++) {
        $id = ((& $rd --get-id | Out-String) -replace '[^0-9]', '')
        if ($id) { break }
        Start-Sleep -Seconds 2
    }
    Log ('ID: ' + $id)
    Save-State 'id' $id; Save-State 'pw' $pw
    if (-not $id) { return 4 }
    return 0
}

function Stage-Register {
    $rd = Get-State 'rd'; if (-not $rd) { $rd = Find-Rd }
    $id = Get-State 'id'; $pw = Get-State 'pw'
    $m = 'false'; if ($pw) { $m = 'true' }
    $wm = 'false'; if ($MASTER) { $wm = 'true' }   # which variant was downloaded (to tell 'OTP chosen' from 'password failed')
    # local IP: IPv4 of the adapter that has the default gateway; external: rd01/whoami (Cloudflare sees the real public address)
    $lip = ''; $mac = ''; $nic = ''
    try {
        foreach ($a in @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Where-Object { $_.DefaultIPGateway })) {
            foreach ($x in @($a.IPAddress)) { if (-not $lip -and $x -match '^\d+\.\d+\.\d+\.\d+$') { $lip = $x; $mac = [string]$a.MACAddress; $nic = [string]$a.Description } }
        }
    } catch {}
    # Wake-on-LAN (best effort): allow the NIC to wake the PC by magic packet; BIOS setting is still up to the PC
    if ($nic) {
        try { & powercfg.exe /deviceenablewake $nic 2>$null | Out-Null } catch {}
        try { Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.MacAddress -replace '-',':' -eq $mac } |
              Set-NetAdapterPowerManagement -WakeOnMagicPacket Enabled -ErrorAction Stop } catch {}
    }
    $eip = ''
    $t = Http-Get ($BASE + '/whoami') ''
    if ($t) { $eip = ([string]$t).Trim() }
    Log ('Local IP: ' + $lip + ', external IP: ' + $eip + ', MAC: ' + $mac)
    $ak = ''; $akf = Join-Path $env:ProgramData 'RustDeskNETH\agent.key'   # reinstall on the same PC: this PC's agent key
    if (Test-Path $akf) { try { $ak = ([IO.File]::ReadAllText($akf)) -replace '[^A-Za-z0-9_-]', '' } catch {} }
    $body = '{"token":' + (JStr $TOKEN) + ',"akey":' + (JStr $ak) + ',"id":' + (JStr $id) + ',"hostname":' + (JStr $env:COMPUTERNAME) + ',"username":' + (JStr $env:USERNAME) +
            ',"os":"windows","master":' + $m + ',"password":' + (JStr $pw) +
            ',"local_ip":' + (JStr $lip) + ',"ext_ip":' + (JStr $eip) + ',"mac":' + (JStr $mac) + ',"want_master":' + $wm +
            (HwJson (Get-HwInfo) @('cpu', 'gpu', 'ram', 'disk', 'nic_type', 'nic_mbps', 'nic_name', 'users', 'logged_user', 'act_status', 'act_channel', 'act_kms', 'act_grace', 'office_name', 'office_status', 'office_channel', 'office_kms', 'office_detail', 'gpu_mem', 'board_vendor', 'board_name', 'cpu_cores', 'cpu_threads', 'ram_type', 'bt_name', 'bt_state')) +
            ',"printers":' + (JStr (Get-PrintersJson)) + ',"scanners":' + (JStr (Get-ScannersJson)) + ',"antivirus":' + (JStr (Get-AvJson)) + ',"software":' + (JStr (Get-SoftwareJson)) + '}'
    $ok = $false
    # rds.* goes straight to our proxy (modern TLS only); rd01 is behind Cloudflare and also accepts old Windows 7 TLS
    for ($i = 0; $i -lt 3 -and -not $ok; $i++) {
        foreach ($u in @($API, $BASE)) {
            Log ('Registering in the panel via ' + $u + '...')
            $ok = Http-Post ($u + '/api/rds/register') $body
            if ($ok) { break }
        }
        if (-not $ok) { Start-Sleep -Seconds 3 }
    }
    if ($ok) { $st = 'ok' } elseif ($pw) { $st = 'noreg:' + $pw } else { $st = 'noreg' }
    if (Install-HwTask $BASE) { Log 'Hardware refresh task installed (startup + every 12 h)' } else { Log 'WARNING: hardware refresh task not installed' }
    Set-Content -Path $Result -Value @($id, $st, $rd) -Encoding Ascii   # 3rd line: NSIS opens RustDesk after the user presses OK
    # Installer downloaded from the admin panel: sign the RustDesk client in to the panel account
    if ($LOGIN_TOKEN) {
        Get-Process rustdesk -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $cdir = Join-Path $env:APPDATA 'RustDesk\config'
        New-Item -ItemType Directory -Force -Path $cdir | Out-Null
        $f = Join-Path $cdir 'RustDesk_local.toml'
        $lines = @()
        if (Test-Path $f) { $lines = @(Get-Content $f | Where-Object { $_ -notmatch '^\s*(access_token|user_info)\s*=' }) }
        $ui = '{"name":"' + $LOGIN_USER + '","display_name":"' + $LOGIN_USER + '","avatar":"","status":1}'
        $ins = @(("access_token = '" + $LOGIN_TOKEN + "'"), ("user_info = '" + $ui + "'"))
        $idx = [Array]::IndexOf([string[]]$lines, '[options]')
        if ($idx -ge 0) {
            $tail = @(); if ($idx + 1 -lt $lines.Count) { $tail = $lines[($idx + 1)..($lines.Count - 1)] }
            $lines = @($lines[0..$idx]) + $ins + $tail
        } else { $lines = $lines + @('', '[options]') + $ins }
        [IO.File]::WriteAllLines($f, [string[]]$lines)
        Log ('Signed in to the panel as ' + $LOGIN_USER)
    }
    if ($rd -and $Stage -eq 'all') { Start-Process -FilePath (Join-Path $env:WINDIR 'explorer.exe') -ArgumentList ('"' + $rd + '"') }   # not elevated
    return 0
}

$rc = 0
switch ($Stage) {
    'prep'     { $rc = Stage-Prep }
    'download' { $rc = Stage-Download }
    'install'  { $rc = Stage-Install }
    'config'   { $rc = Stage-Config }
    'register' { $rc = Stage-Register }
    default {
        foreach ($s in @('Prep', 'Download', 'Install', 'Config', 'Register')) {
            $rc = & ('Stage-' + $s); if ($rc -ne 0) { break }
        }
    }
}
exit $rc
