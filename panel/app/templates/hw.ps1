param([switch]$Task, [switch]$Poll)
# RustDesk NETH: update hardware / printers / IP / MAC of this PC in the panel WITHOUT reinstalling RustDesk.
# Run in PowerShell as administrator (then it also installs the automatic refresh at startup and every 12 h):
#   iex ((New-Object Net.WebClient).DownloadString('__BASE__/hw.ps1'))
# ASCII only, PowerShell 2.0 compatible (Windows 7+).
$API = '__API__'; $BASE = '__BASE__'; $TOKEN = '__TOKEN__'; $HWV = '__HWV__'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]([int]3072 -bor 768 -bor 192) } catch {}
function JStr([string]$s) {
    if ($s -eq $null) { $s = '' }
    $o = New-Object Text.StringBuilder
    foreach ($c in $s.ToCharArray()) { $n = [int]$c
        if ($c -eq '"' -or $c -eq '\') { [void]$o.Append('\').Append($c) } elseif ($n -lt 32 -or $n -gt 126) { [void]$o.Append('\u' + $n.ToString('x4')) } else { [void]$o.Append($c) } }
    return '"' + $o.ToString() + '"'
}
# agent key: the panel issues it to this PC once (akey_new); after that the shared TOKEN is refused for this PC.
# Kept readable by SYSTEM and Administrators only; a non-admin run does not ask for a key (ak=false) so it is never lost.
$AKF = Join-Path $env:ProgramData 'RustDeskNETH\agent.key'; $AK = ''; $AKC = 'false'
try { if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $AKC = 'true' } } catch {}
if ($AKC -eq 'true' -and (Test-Path $AKF)) { try { $AK = ([IO.File]::ReadAllText($AKF)) -replace '[^A-Za-z0-9_-]', '' } catch {} }
function Auth { return '"token":' + (JStr $TOKEN) + ',"akey":' + (JStr $script:AK) + ',"ak":' + $AKC }
function Ak-Save([string]$r) {
    if ($AKC -ne 'true' -or -not $r) { return }
    if ($r -match '"akey_new"\s*:\s*"([A-Za-z0-9_-]{20,100})"') {
        $k = $matches[1]
        try {
            $d = Split-Path $AKF; if (-not (Test-Path $d)) { [void](New-Item -ItemType Directory -Path $d -Force) }
            [IO.File]::WriteAllText($AKF, $k)
            & icacls.exe $AKF /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' 2>$null | Out-Null
            $script:AK = $k
        } catch {}
    }
}
function Post([string]$url, [string]$json) {
    try { $wc = New-Object Net.WebClient; $wc.Headers.Add('Content-Type', 'application/json; charset=utf-8'); $wc.Encoding = [Text.Encoding]::UTF8; return $wc.UploadString($url, 'POST', $json) } catch {}
    try { $x = New-Object -ComObject 'Msxml2.XMLHTTP'; $x.open('POST', $url, $false); $x.setRequestHeader('Content-Type', 'application/json; charset=utf-8'); $x.send($json); if ($x.status -lt 300) { return [string]$x.responseText } } catch {}
    return $null
}
function Say([string]$m, [string]$c = 'Gray') { if (-not $Task) { Write-Host $m -ForegroundColor $c } }
# ---- software jobs from the panel (install / upgrade / uninstall); every value arrives base64-encoded
function Sw-Run([string]$exe, [string]$argline) {
    if ($argline) { $p = Start-Process -FilePath $exe -ArgumentList $argline -Wait -PassThru -WindowStyle Hidden }
    else { $p = Start-Process -FilePath $exe -Wait -PassThru -WindowStyle Hidden }
    return [int]$p.ExitCode
}
function Sw-Code([int]$code) {   # 0 ok, 3010/1641 ok + reboot needed
    if ($code -eq 0 -or $code -eq 3010 -or $code -eq 1641) { return @($true, '') }
    return @($false, '')
}
function Sw-Fetch([string]$url, [string]$jid, [string]$fname, [string]$sha) {
    $dir = Join-Path $env:ProgramData 'RustDeskNETH\pkgs'; if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $safe = ($fname -replace '[^\w.\-]', '_'); if (-not $safe) { $safe = 'installer.bin' }
    $f = Join-Path $dir ($jid + '-' + $safe)
    (New-Object Net.WebClient).DownloadFile($url, $f)
    if ($sha) {
        $fs = [IO.File]::OpenRead($f)
        try { $hh = ([BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash($fs))).Replace('-', '').ToLower() } finally { $fs.Close() }
        if ($hh -ne $sha.ToLower()) { Remove-Item $f -Force; throw ('checksum mismatch (' + $hh + ')') }
    }
    return $f
}
function Sw-Winget {
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue; if ($c) { return $c.Path }
    $w = @(Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
    if ($w.Count) { return $w[0].FullName }
    throw 'winget is not installed on this PC'
}
function Sw-Script([string]$text, [string]$jid) {
    $f = Join-Path $env:TEMP ('rds-job-' + $jid + '.ps1'); [IO.File]::WriteAllText($f, $text, (New-Object Text.UTF8Encoding($true)))
    try { return (Sw-Run 'powershell.exe' ('-NoProfile -ExecutionPolicy Bypass -File "' + $f + '"')) } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}
function Sw-UninstallByName([string]$name, [string]$extra) {
    $all = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        foreach ($e in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) { if ([string]$e.DisplayName) { $all += $e } }
    }
    $hit = @($all | Where-Object { ([string]$_.DisplayName).Trim() -eq $name.Trim() })
    if (-not $hit.Count) { $hit = @($all | Where-Object { ([string]$_.DisplayName) -like ($name.Trim() + '*') }) }
    if (-not $hit.Count) { throw ('program not found: ' + $name) }
    $e = $hit[0]
    if ($e.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' -and $e.WindowsInstaller -eq 1) { return (Sw-Run 'msiexec.exe' ('/x ' + $e.PSChildName + ' /qn /norestart ' + $extra)) }
    $q = [string]$e.QuietUninstallString
    if ($q) { return (Sw-Run 'cmd.exe' ('/c "' + $q + ' ' + $extra + '"')) }
    $u = [string]$e.UninstallString
    if (-not $u) { throw 'no uninstall command in the registry' }
    if ($u -match 'msiexec') { $u = ($u -replace '/I', '/X'); return (Sw-Run 'cmd.exe' ('/c "' + $u + ' /qn /norestart ' + $extra + '"')) }
    return (Sw-Run 'cmd.exe' ('/c "' + $u + ' ' + $extra + '"'))
}
function Sw-Job([string]$r) {
    function JF([string]$k) { if ($r -match ('"' + $k + '"\s*:\s*"([^"]*)"')) { return $matches[1] }; return '' }
    function D64([string]$k) { $v = JF ($k + '_b64'); if (-not $v) { return '' }; try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v)) } catch { return '' } }
    $jid = JF 'id'; $act = JF 'act'; $kind = JF 'kind'; $sha = JF 'sha'; $fname = JF 'fname'
    $src = D64 'src'; $ia = D64 'args'; $uk = D64 'ukind'; $ua = D64 'uargs'; $nm = D64 'name'; $url = D64 'url'; $post = D64 'post'
    $ok = $false; $msg = ''; $code = -1; $wgnote = ''
    try {
        $code = 0
        if ($kind -eq 'winget') {
            $wg = Sw-Winget; $base = ' --id "' + $src + '" -e --silent --accept-source-agreements --disable-interactivity'
            if ($act -eq 'uninstall') { $code = Sw-Run $wg ('uninstall' + $base + ' ' + $ua) }
            elseif ($act -eq 'upgrade') { $code = Sw-Run $wg ('upgrade' + $base + ' --accept-package-agreements ' + $ia) }
            else { $code = Sw-Run $wg ('install' + $base + ' --accept-package-agreements --scope machine ' + $ia) }
            # winget: 0x8A15002B = no newer version, 0x8A150061 = already installed -- not an error
            if ($code -eq -1978335189) { $code = 0; $wgnote = 'winget: already the latest version' }
            elseif ($code -eq -1978335135) { $code = 0; $wgnote = 'winget: already installed' }
        } elseif ($act -eq 'uninstall') {
            if ($uk -eq 'cmd' -and $ua) { $code = Sw-Run 'cmd.exe' ('/c "' + $ua + '"') }
            elseif ($uk -eq 'script' -and $ua) { $code = Sw-Script $ua $jid }
            else { $code = Sw-UninstallByName $nm $ua }
        } elseif ($kind -eq 'ps1') { $code = Sw-Script $src $jid }
        elseif ($kind -eq 'msi' -or $kind -eq 'exe') {
            if (-not $url) { throw 'no installer file or URL' }
            if (-not $fname) { $fname = [IO.Path]::GetFileName(([uri]$url).AbsolutePath) }
            $f = Sw-Fetch $url $jid $fname $sha
            try {
                if ($kind -eq 'msi') { $code = Sw-Run 'msiexec.exe' ('/i "' + $f + '" /qn /norestart ' + $ia) } else { $code = Sw-Run $f $ia }
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        } else { throw ('unsupported job type: ' + $kind) }
        $rc = Sw-Code $code; $ok = $rc[0]; $msg = $rc[1]; if ($wgnote) { $msg = $wgnote }
        # settings after a successful install / upgrade: the package's post-install PowerShell script
        if ($ok -and $act -ne 'uninstall' -and $post) { $pc = Sw-Script $post ($jid + 'p'); if ($pc -ne 0) { $ok = $false; $code = $pc; $msg = 'post-install script failed' } }
    } catch { $ok = $false; $msg = [string]$_.Exception.Message }
    $okj = 'false'; if ($ok) { $okj = 'true' }
    $res = '{' + (Auth) + ',"id":' + (JStr $id) + ',"job":' + (JStr $jid) + ',"ok":' + $okj + ',"code":' + (JStr ([string]$code)) + ',"msg":' + (JStr $msg) + '}'
    $x = Post ($API + '/api/rds/jobresult') $res; if (-not $x) { [void](Post ($BASE + '/api/rds/jobresult') $res) }
}

__HWPS__
$rd = ''
foreach ($p in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($p -and (Test-Path (Join-Path $p 'RustDesk\rustdesk.exe'))) { $rd = Join-Path $p 'RustDesk\rustdesk.exe'; break } }
if (-not $rd) { Say 'RustDesk is not installed on this PC' 'Red'; return }
$id = ((& $rd --get-id | Out-String) -replace '[^0-9]', '')
if (-not $id) {
    foreach ($f in @((Join-Path $env:APPDATA 'RustDesk\config\RustDesk.toml'), 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk.toml')) {
        if (-not $id -and (Test-Path $f)) { $m = [regex]::Match([IO.File]::ReadAllText($f), "(?m)^id\s*=\s*'(\d+)'"); if ($m.Success) { $id = $m.Groups[1].Value } }
    }
}
if (-not $id) { Say 'Could not read RustDesk ID' 'Red'; return }
# api-server in RustDesk must match the panel (e.g. after the panel moved): re-apply the server config, at most once a day
if ($AKC -eq 'true') {
    try {
        $cf = Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml'
        $cur = $null
        if (Test-Path $cf) { $m = [regex]::Match([IO.File]::ReadAllText($cf), "(?m)^api-server\s*=\s*'([^']*)'"); $cur = ''; if ($m.Success) { $cur = $m.Groups[1].Value } }
        if ($cur -ne $null -and $cur -ne $API) {
            $sf = Join-Path $env:ProgramData 'RustDeskNETH\cfg-applied'
            $now = [int64](([datetime]::UtcNow - [datetime]'1970-01-01').TotalSeconds); [int64]$last = 0
            if (Test-Path $sf) { [void][int64]::TryParse(([IO.File]::ReadAllText($sf)).Trim(), [ref]$last) }
            if ($now - $last -ge 86400) {
                $d = Split-Path $sf; if (-not (Test-Path $d)) { [void](New-Item -ItemType Directory -Path $d -Force) }
                [IO.File]::WriteAllText($sf, [string]$now)
                & $rd --config '__CFG__' | Out-Null
                # the service keeps settings in memory - restart it to pick up the new config
                Restart-Service -Name 'RustDesk' -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}
if ($Poll) {
    # every 5 min: ask the panel for commands (only "update" for now)
    $rdv = ''; try { $rdv = ([string](Get-Item $rd).VersionInfo.ProductVersion) -replace '[^0-9.]', '' } catch {}
    $q = '{' + (Auth) + ',"id":' + (JStr $id) + ',"rdv":' + (JStr $rdv) + '}'
    $r = Post ($API + '/api/rds/poll') $q
    if (-not $r) { $r = Post ($BASE + '/api/rds/poll') $q }
    Ak-Save $r
    if ($r -and $r -match '"cmd"\s*:\s*"(shutdown|reboot)"') {
        $what = $matches[1]
        $res = '{' + (Auth) + ',"id":' + (JStr $id) + ',"ok":true,"action":"' + $what + '","msg":""}'
        $x = Post ($API + '/api/rds/cmdresult') $res; if (-not $x) { [void](Post ($BASE + '/api/rds/cmdresult') $res) }
        $sw = '/s'; if ($what -eq 'reboot') { $sw = '/r' }
        $dl = 60; if ($r -match '"delay"\s*:\s*"(\d+)"') { $dl = [int]$matches[1] }
        $msg = ''; if ($r -match '"msg_b64"\s*:\s*"([^"]*)"') { try { $msg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) } catch {} }
        if (-not $msg) { $msg = 'The administrator has requested this action from the RDS panel (RustDesk).' }
        $msg = ($msg -replace '"', "'"); if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
        & shutdown.exe $sw /f /t $dl /c $msg 2>$null | Out-Null
        return
    }
    if ($r -and $r -match '"cmd"\s*:\s*"update"') {
        $err = Invoke-RdUpdate $BASE
        $rd2 = ''
        foreach ($p in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($p -and (Test-Path (Join-Path $p 'RustDesk\rustdesk.exe'))) { $rd2 = Join-Path $p 'RustDesk\rustdesk.exe'; break } }
        $ver = ''; if ($rd2) { $ver = [string](Get-Item $rd2).VersionInfo.ProductVersion }
        $ok = 'true'; if ($err) { $ok = 'false' }
        $res = '{' + (Auth) + ',"id":' + (JStr $id) + ',"ok":' + $ok + ',"version":' + (JStr $ver) + ',"msg":' + (JStr $err) + '}'
        $x = Post ($API + '/api/rds/cmdresult') $res; if (-not $x) { [void](Post ($BASE + '/api/rds/cmdresult') $res) }
    }
    $me0 = Join-Path $env:ProgramData 'RustDeskNETH\hw.ps1'
    # "Refresh data" from the panel's Hardware card / a software job (then the installed-programs list is refreshed)
    if ($r -and $r -match '"cmd"\s*:\s*"hw"') { if (Test-Path $me0) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $me0 -Task 2>$null | Out-Null }; return }
    if ($r -and $r -match '"job"\s*:\s*\{') { Sw-Job $r; if (Test-Path $me0) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $me0 -Task 2>$null | Out-Null }; return }
    # the panel has a newer collector: fetch it and collect right away (same version is retried at most every 30 min)
    if ($r -and $r -match '"hwv_win"\s*:\s*"([0-9a-f]+)"' -and $matches[1] -ne $HWV) {
        $want = $matches[1]; $dir = Join-Path $env:ProgramData 'RustDeskNETH'; $me = Join-Path $dir 'hw.ps1'; $mark = Join-Path $dir 'hwv.try'
        $skip = $false
        if (Test-Path $mark) { if (([string](Get-Content $mark -TotalCount 1)).Trim() -eq $want -and ((Get-Date) - (Get-Item $mark).LastWriteTime).TotalMinutes -lt 30) { $skip = $true } }
        if (-not $skip -and (Test-Path $me)) {
            Set-Content -Path $mark -Value $want
            try {
                $tmp = $me + '.new'; (New-Object Net.WebClient).DownloadFile($BASE + '/hw.ps1', $tmp)
                if ((Get-Item $tmp).Length -gt 2000 -and (Get-Content $tmp -TotalCount 1) -match '^param') { Move-Item $tmp $me -Force } else { Remove-Item $tmp -Force }
            } catch {}
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $me -Task 2>$null | Out-Null
        }
    }
    return
}
if ($Task) {
    # self-update: the scheduled copy refreshes itself for the next run (fixes reach PCs without re-running the command)
    try {
        $me = Join-Path $env:ProgramData 'RustDeskNETH\hw.ps1'; $tmp = $me + '.new'
        (New-Object Net.WebClient).DownloadFile($BASE + '/hw.ps1', $tmp)
        if ((Get-Item $tmp).Length -gt 2000 -and (Get-Content $tmp -TotalCount 1) -match '^param') { Move-Item $tmp $me -Force } else { Remove-Item $tmp -Force }
    } catch {}
}
$h = Get-HwInfo
$body = '{' + (Auth) + ',"id":' + (JStr $id) + (HwJson $h) + ',"printers":' + (JStr (Get-PrintersJson -NoDefault:$Task)) + ',"scanners":' + (JStr (Get-ScannersJson)) + ',"antivirus":' + (JStr (Get-AvJson)) + ',"software":' + (JStr (Get-SoftwareJson)) + '}'
$r = Post ($API + '/api/rds/hwinfo') $body
if (-not $r) { $r = Post ($BASE + '/api/rds/hwinfo') $body }
Ak-Save $r
if ($r) { Say ('OK: ID ' + $id + ' | ' + $h.cpu + ' | ' + $h.gpu + ' | RAM ' + [math]::Round([double]$h.ram / 1GB) + ' GB | ' + $h.disk + ' | ' + $h.nic_type + ' ' + $h.nic_mbps + ' Mbit/s | MAC ' + $h.mac) 'Green' }
else { Say 'Server did not answer' 'Red' }
if (-not $Task) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Say 'Automatic refresh NOT installed: run PowerShell as administrator and repeat the command.' 'Yellow' }
    elseif (Install-HwTask $BASE) { Say 'Automatic refresh installed: at startup and every 12 hours (Task Scheduler: RustDeskNETH).' 'Green' }
    else { Say 'Could not install the automatic refresh task.' 'Yellow' }
}
