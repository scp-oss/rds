# --- hardware info (shared by setup.ps1 and hw.ps1; ASCII only, PowerShell 2.0 compatible)
# cpu, gpu, ram (bytes), disk (system disk only), nic_type (ethernet/wifi/other), nic_mbps, nic_name, mac, local_ip
function Get-HwInfo {
    $h = @{ cpu = ''; gpu = ''; ram = ''; disk = ''; nic_type = ''; nic_mbps = ''; nic_name = ''; mac = ''; local_ip = '' }
    try { $h.cpu = (([string](@(Get-WmiObject Win32_Processor)[0].Name)) -replace '\s+', ' ').Trim() } catch {}
    try {
        $g = @()
        foreach ($v in @(Get-WmiObject Win32_VideoController)) {
            $n = ([string]$v.Name).Trim()
            if ($n -and $n -notmatch 'Basic Display|Basic Render|Remote|Virtual|Mirage|DameWare|Parsec|RustDesk|Citrix|VNC|Hyper-V|IddCx|Indirect') { $g += $n }
        }
        $h.gpu = (($g | Select-Object -Unique) -join '; ')
    } catch {}
    # video memory per GPU, same order as gpu. Win32_VideoController.AdapterRAM is 32-bit (caps at 4 GB), so the driver's
    # registry key is used: HardwareInformation.qwMemorySize (QWORD) or .MemorySize. Integrated graphics are skipped
    # (their "video memory" is a slice of system RAM).
    $h.gpu_mem = ''
    try {
        $mem = @{}
        foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue; if (-not $p -or -not $p.DriverDesc) { continue }
            $b = 0
            try { $q = $p.'HardwareInformation.qwMemorySize'; if ($q) { $b = [double]$q } } catch {}
            if (-not $b) { try { $m = $p.'HardwareInformation.MemorySize'; if ($m -is [byte[]]) { $b = [double][BitConverter]::ToUInt32($m, 0) } elseif ($m) { $b = [double]$m } } catch {} }
            if ($b -gt 0) { $mem[([string]$p.DriverDesc).Trim()] = $b }
        }
        $out = @()
        foreach ($n in @($h.gpu -split '; ')) {
            if (-not $n) { continue }
            $v = ''
            if ($n -notmatch 'Intel.*(UHD|HD Graphics|Iris)|^(AMD )?Radeon\(TM\) Graphics$|Radeon Graphics$|Vega \d+ Graphics|Microsoft' -and $mem.ContainsKey($n)) { $v = [string]$mem[$n] }
            $out += $v
        }
        $h.gpu_mem = ($out -join '; ')
    } catch {}
    # Bluetooth adapter (the radio itself: USB\ or PCI\ device of class Bluetooth, not paired devices BTHENUM\...).
    # bt_state: ok / disabled (switched off in Device Manager, error 22) / error (driver problem) / none (no adapter)
    $h.bt_name = ''; $h.bt_state = ''
    try {
        $bt = @(Get-WmiObject Win32_PnPEntity -Filter "ClassGuid='{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'" | Where-Object { ([string]$_.DeviceID) -match '^(USB|PCI|ACPI|SD|UART)\\' -and ([string]$_.Name) -notmatch 'Enumerator|RFCOMM|LE Enum' })
        if ($bt.Count) {
            $b = $bt[0]; foreach ($x in $bt) { if ([int]$x.ConfigManagerErrorCode -eq 0) { $b = $x; break } }
            $h.bt_name = ([string]$b.Name).Trim(); $ec = [int]$b.ConfigManagerErrorCode
            if ($ec -eq 0) { $h.bt_state = 'ok' } elseif ($ec -eq 22) { $h.bt_state = 'disabled' } else { $h.bt_state = 'error' }
        } else { $h.bt_state = 'none' }
    } catch {}
    # motherboard: vendor + product from the board's SMBIOS data
    $h.board_vendor = ''; $h.board_name = ''
    try { $bb = @(Get-WmiObject Win32_BaseBoard)[0]; $h.board_vendor = ([string]$bb.Manufacturer).Trim(); $h.board_name = ([string]$bb.Product).Trim() } catch {}
    # CPU cores / threads (all sockets)
    $h.cpu_cores = ''; $h.cpu_threads = ''
    try { $co = 0; $th = 0; foreach ($p in @(Get-WmiObject Win32_Processor)) { $co += [int]$p.NumberOfCores; $th += [int]$p.NumberOfLogicalProcessors }
          if ($co) { $h.cpu_cores = [string]$co }; if ($th) { $h.cpu_threads = [string]$th } } catch {}
    # RAM size + type (SMBIOSMemoryType: 20 DDR, 21 DDR2, 24 DDR3, 26 DDR4, 34 DDR5, 27/28 LPDDR, 29 LPDDR2, 30 LPDDR3, 35 LPDDR5)
    $h.ram_type = ''
    try {
        $sum = 0; $types = @{}
        foreach ($m in @(Get-WmiObject Win32_PhysicalMemory)) {
            $sum += [double]$m.Capacity
            $t = [int]$m.SMBIOSMemoryType; if (-not $t) { $t = [int]$m.MemoryType }
            $nm = @{ 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }[$t]
            if ($nm) { $types[$nm] = 1 }
        }
        $h.ram_type = (@($types.Keys) | Sort-Object) -join '/'
        if ($sum -gt 0) { $h.ram = [string]$sum } else { $h.ram = [string](Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory }
    } catch {}
    # system disk: C: -> partition -> physical disk index
    $idx = $null; $model = ''; $size = 0
    try {
        $sd = $env:SystemDrive
        foreach ($p in @(Get-WmiObject -Query ("ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + $sd + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"))) {
            foreach ($d in @(Get-WmiObject -Query ("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $p.DeviceID + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))) {
                if ($idx -eq $null) { $idx = [int]$d.Index; $model = ([string]$d.Model).Trim(); $size = [double]$d.Size }
            }
        }
    } catch {}
    $t = ''
    try {
        foreach ($d in @(Get-WmiObject -Namespace 'root\Microsoft\Windows\Storage' -Class MSFT_PhysicalDisk -ErrorAction Stop)) {
            if ($idx -ne $null -and [string]$d.DeviceId -ne [string]$idx) { continue }
            switch ([int]$d.MediaType) { 3 { $t = 'HDD' } 4 { $t = 'SSD' } 5 { $t = 'SCM' } }
            if ([int]$d.BusType -eq 17) { if ($t -eq 'HDD') { $t = 'NVMe HDD' } else { $t = 'NVMe SSD' } }
            if (-not $model) { $model = ([string]$d.FriendlyName).Trim() }
            if (-not $size) { $size = [double]$d.Size }
            break
        }
    } catch {}
    if (-not $t) { if ($model -match 'NVMe') { $t = 'NVMe SSD' } elseif ($model -match 'SSD') { $t = 'SSD' } else { $t = 'Disk' } }
    if ($size -gt 0) { $h.disk = ($t + ' ' + [math]::Round($size / 1e9) + ' GB (' + $model + ')') }
    # network: adapter with the default gateway
    try {
        foreach ($a in @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Where-Object { $_.DefaultIPGateway })) {
            if ($h.mac) { break }
            foreach ($x in @($a.IPAddress)) { if (-not $h.local_ip -and $x -match '^\d+\.\d+\.\d+\.\d+$') { $h.local_ip = $x } }
            $h.mac = [string]$a.MACAddress
            $n = Get-WmiObject Win32_NetworkAdapter -Filter ('Index=' + $a.Index)
            if ($n) {
                $h.nic_name = ([string]$n.Name).Trim()
                if ($n.Speed) { $h.nic_mbps = [string][math]::Round([double]$n.Speed / 1e6) }
                $h.nic_type = 'ethernet'
                if ($h.nic_name -match 'Wi-?Fi|Wireless|WLAN|802\.11') { $h.nic_type = 'wifi' }
                try {   # Windows 8+: physical medium is exact (9 = 802.11, 14 = 802.3)
                    $na = Get-WmiObject -Namespace 'root\StandardCimv2' -Class MSFT_NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $n.InterfaceIndex }
                    if ($na) { switch ([int]$na.NdisPhysicalMedium) { 9 { $h.nic_type = 'wifi' } 14 { $h.nic_type = 'ethernet' } } }
                } catch {}
            }
        }
    } catch {}
    # user accounts on this PC (enabled local accounts, built-ins skipped) and who is signed in now
    $h.users = ''; $h.logged_user = ''
    try {
        $u = @()
        foreach ($a in @(Get-WmiObject Win32_UserAccount -Filter ("LocalAccount=TRUE AND Disabled=FALSE"))) {
            $n = [string]$a.Name
            if ($n -notmatch '^(Administrator|Guest|DefaultAccount|WDAGUtilityAccount|HomeGroupUser\$|defaultuser\d*)$') { $u += $n }
        }
        $h.users = ($u -join '; ')
    } catch {}
    try { $h.logged_user = [string](Get-WmiObject Win32_ComputerSystem).UserName } catch {}
    # Windows activation: LicenseStatus 0 unlicensed, 1 licensed, 2-6 grace/notification; channel from Description
    $h.act_status = ''; $h.act_channel = ''; $h.act_kms = ''; $h.act_grace = ''
    try {
        $lp = @(Get-WmiObject SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop)
        $best = $null; foreach ($x in $lp) { if ($best -eq $null -or [int]$x.LicenseStatus -eq 1) { $best = $x } }
        if ($best) {
            $h.act_status = [string][int]$best.LicenseStatus
            $ds = [string]$best.Description
            if ($ds -match 'VOLUME_KMSCLIENT') { $h.act_channel = 'KMS' } elseif ($ds -match 'VOLUME_MAK') { $h.act_channel = 'MAK' }
            elseif ($ds -match 'OEM') { $h.act_channel = 'OEM' } elseif ($ds -match 'RETAIL') { $h.act_channel = 'Retail' }
            elseif ($ds -match 'TIMEBASED_EVAL|EVAL') { $h.act_channel = 'Evaluation' } else { $h.act_channel = ($ds -split ',')[-1].Trim() }
            if ($h.act_channel -eq 'KMS') {
                $k = [string]$best.KeyManagementServiceMachine; if (-not $k) { $k = [string]$best.DiscoveredKeyManagementServiceMachineName }
                $h.act_kms = $k
            }
            if ($best.GracePeriodRemaining) { $h.act_grace = [string][int]$best.GracePeriodRemaining }
        } else { $h.act_status = '0' }
    } catch {}
    # MS Office: name from installed programs (Click-to-Run / MSI suite), licence from the same licensing service
    # (ApplicationID 0ff1ce15-... ; Office 2010/2013 on old Windows use OfficeSoftwareProtectionProduct).
    # Empty office_name and office_status = Office not installed (panel shows nothing).
    $h.office_name = ''; $h.office_status = ''; $h.office_channel = ''; $h.office_kms = ''; $h.office_detail = ''
    try {
        $names = @()
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
            foreach ($e in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
                $dn = [string]$e.DisplayName
                if ($dn -match '^Microsoft (Office|365)' -and $dn -notmatch 'Click-to-Run|Language|Proofing|MUI|Viewer|Runtime|Interop|Components|Shared|Visio|Project|Live Meeting|Access database engine|OneDrive|Teams|Lync|Skype|SharePoint|Tools|Validation|Web Apps|Outlook Social|Primary Interop') {
                    $names += (($dn -replace '\s+-\s+[a-z]{2}-[a-z]{2}$', '') -replace '^Microsoft\s+', '').Trim()
                }
            }
        }
        if ($names.Count) { $h.office_name = ($names | Sort-Object -Unique | Select-Object -First 2) -join '; ' }
        $op = @()
        foreach ($cls in @('SoftwareLicensingProduct', 'OfficeSoftwareProtectionProduct')) {
            try { $op += @(Get-WmiObject $cls -Filter "ApplicationID='0ff1ce15-a989-479d-af46-f275c6370663' AND PartialProductKey IS NOT NULL" -ErrorAction Stop) } catch {}
        }
        $best = $null; foreach ($x in $op) { if ($best -eq $null -or [int]$x.LicenseStatus -eq 1) { $best = $x } }
        if ($best) {
            $h.office_status = [string][int]$best.LicenseStatus
            $ds = [string]$best.Description
            if ($ds -match 'VOLUME_KMSCLIENT') { $h.office_channel = 'KMS' } elseif ($ds -match 'VOLUME_MAK') { $h.office_channel = 'MAK' }
            elseif ($ds -match 'OEM') { $h.office_channel = 'OEM' } elseif ($ds -match 'RETAIL') { $h.office_channel = 'Retail' }
            elseif ($ds -match 'SUBSCRIPTION') { $h.office_channel = 'Subscription' } elseif ($ds -match 'EVAL|TRIAL') { $h.office_channel = 'Trial' }
            if ($h.office_channel -eq 'KMS') {
                $kk = [string]$best.KeyManagementServiceMachine; if (-not $kk) { $kk = [string]$best.DiscoveredKeyManagementServiceMachineName }
                $h.office_kms = $kk
            }
            # no name in installed programs (rare): build it from the licence, "Office 24, Office24StandardVL_KMS_Client_AE edition"
            if (-not $h.office_name -and ([string]$best.Name) -cmatch 'Office (\d\d),\s*Office\d\d([A-Za-z]+?)(VL|R|_)') {
                $yr = @{ '14' = '2010'; '15' = '2013'; '16' = '2016' }[$matches[1]]; if (-not $yr) { $yr = '20' + $matches[1] }
                $h.office_name = 'Office ' + $yr + ' ' + $matches[2]
            }
        }
        # Retail Office 2021/2024 activated with a Microsoft account (and Microsoft 365) keep the licence in the user's
        # profile ("vNext": %LOCALAPPDATA%\Microsoft\Office\Licenses); the licensing service then still lists the SKU
        # in notification mode, although Office itself says "Product activated".
        $vnext = 0
        foreach ($d in @(Get-ChildItem 'C:\Users' -ErrorAction SilentlyContinue)) {
            $lic = Join-Path $d.FullName 'AppData\Local\Microsoft\Office\Licenses'
            if (Test-Path $lic) { $vnext += @(Get-ChildItem $lic -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }).Count }
        }
        $sppd = @(); foreach ($x in $op) { $sppd += (([string]$x.Name) -replace '^Office \d+,\s*', '' -replace ' edition$', '') + '=' + [int]$x.LicenseStatus }
        $h.office_detail = 'SPP: ' + ($sppd -join ', ') + '; vNext: ' + $vnext
        if ($h.office_name -and $h.office_status -ne '1' -and $vnext -gt 0) { $h.office_status = 'vnext' }
        elseif (-not $best -and $h.office_name -match '365') { $h.office_status = 'sub' }   # Microsoft 365: licence lives in the user's account
        elseif (-not $best -and $h.office_name) { $h.office_status = '0' }                      # installed, no product key
    } catch {}
    return $h
}
# antivirus -> JSON array string: [{"name","enabled":true|false,"uptodate":true|false|null}]
# workstations: root\SecurityCenter2 AntiVirusProduct (productState: byte 2 0x10 = on, byte 3 0x00 = signatures up to date);
# servers (no Security Center): Windows Defender status
function Get-AvJson {
    $items = @(); $seen = @{}
    try {
        foreach ($a in @(Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Stop)) {
            $n = ([string]$a.displayName).Trim(); if (-not $n -or $seen.ContainsKey($n)) { continue }; $seen[$n] = 1
            $st = [int]$a.productState
            $on = 'false'; if ((($st -shr 8) -band 0xFF) -band 0x10) { $on = 'true' }
            $up = 'true'; if (($st -band 0xFF) -ne 0) { $up = 'false' }
            $items += ('{"name":' + (JStr $n) + ',"enabled":' + $on + ',"uptodate":' + $up + '}')
        }
    } catch {}
    if ($items.Count -eq 0) {
        try {
            $d = Get-WmiObject -Namespace 'root\Microsoft\Windows\Defender' -Class MSFT_MpComputerStatus -ErrorAction Stop
            if ($d) {
                $on = 'false'; if ($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) { $on = 'true' }
                $up = 'null'; if ($d.AntivirusSignatureAge -ne $null) { if ([int]$d.AntivirusSignatureAge -le 7) { $up = 'true' } else { $up = 'false' } }
                $items += ('{"name":"Microsoft Defender","enabled":' + $on + ',"uptodate":' + $up + '}')
            }
        } catch {}
    }
    return ('[' + ($items -join ',') + ']')
}
# installed software (Uninstall registry, 64- and 32-bit; system components and updates skipped) -> [{"n","v","p"}]
function Get-SoftwareJson {
    $seen = @{}; $items = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        try {
            foreach ($p in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
                $n = ([string]$p.DisplayName).Trim()
                if (-not $n -or $p.SystemComponent -eq 1 -or $p.ParentKeyName -or [string]$p.ReleaseType -match 'Update|Hotfix') { continue }
                if ($n -match '^(Security Update|Update for|Hotfix for)' -or $seen.ContainsKey($n)) { continue }
                $seen[$n] = 1
                $items += ('{"n":' + (JStr $n) + ',"v":' + (JStr ([string]$p.DisplayVersion)) + ',"p":' + (JStr ([string]$p.Publisher)) + '}')
                if ($items.Count -ge 500) { break }
            }
        } catch {}
    }
    return ('[' + ($items -join ',') + ']')
}
# update RustDesk on request from the panel (agent: task every 5 min, hw.ps1 -Poll). Uses the installer stages
# prep/download/install from /update.ps1 (= setup.ps1): server settings, password and registration stay untouched.
function Invoke-RdUpdate([string]$base) {
    $dir = Join-Path $env:ProgramData 'RustDeskNETH\update'
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $f = Join-Path $dir 'update.ps1'
    try { (New-Object Net.WebClient).DownloadFile($base + '/update.ps1', $f) } catch {
        try { $x = New-Object -ComObject 'Msxml2.XMLHTTP'; $x.open('GET', $base + '/update.ps1', $false); $x.send(); [IO.File]::WriteAllText($f, [string]$x.responseText) } catch { return 'download of update.ps1 failed' }
    }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    foreach ($st in @('prep', 'download', 'install')) {
        & $ps -NoProfile -ExecutionPolicy Bypass -File $f -Stage $st -Dir $dir 2>&1 | Out-File (Join-Path $dir ($st + '.log')) -Encoding ASCII
        if ($LASTEXITCODE -ne 0) { return ('stage ' + $st + ' failed (code ' + $LASTEXITCODE + ')') }
    }
    return ''
}
# printers -> JSON array string: [{"name","type":"usb|network|other","ip","mac","default"}]; virtual printers skipped
$script:NetPrinters = @()
function Get-PrintersJson([switch]$NoDefault) {   # -NoDefault: run as SYSTEM, its default printer means nothing
    $items = @(); $script:NetPrinters = @()
    try {
        $ports = @{}
        foreach ($p in @(Get-WmiObject Win32_TCPIPPrinterPort)) { $ports[[string]$p.Name] = [string]$p.HostAddress }
        # USB printers that are physically present right now (Win32_PnPEntity lists only present devices)
        $usbNow = @(); foreach ($u in @(Get-WmiObject Win32_PnPEntity -Filter "DeviceID LIKE 'USBPRINT%'")) { $usbNow += [string]$u.Name }
        foreach ($pr in @(Get-WmiObject Win32_Printer)) {
            $name = ([string]$pr.Name).Trim(); $port = [string]$pr.PortName
            if ($name -match 'PDF|XPS|OneNote|Fax|Send To|Microsoft Print|Snagit|AnyDesk|RustDesk' -or $port -match '^(PORTPROMPT|FILE|nul|SHRFAX|XPS|Microsoft\.)') { continue }
            # printers redirected from the PC you connect FROM (RDP / remote session: port TSnnn, name "... (redirected N)")
            if ($port -match '^TS\d+$' -or $name -match '\((redirected|\u043f\u0435\u0440\u0435\u043d\u0430\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043e)\b') { continue }
            $type = 'other'; $ip = ''
            if ($port -match '^USB|^DOT4|^LPT') { $type = 'usb' }
            elseif ($ports.ContainsKey($port)) { $type = 'network'; $ip = $ports[$port] }
            elseif ($port -match '^WSD-') { $type = 'network' }
            elseif ($port -match '^\\\\([^\\]+)\\') { $type = 'network'; $ip = $matches[1] }
            elseif ($port -match '^(IP_)?(\d+\.\d+\.\d+\.\d+)') { $type = 'network'; $ip = $matches[2] }
            $mac = ''
            if ($ip -match '^\d+\.\d+\.\d+\.\d+$') {
                try { & ping.exe -n 1 -w 500 $ip 2>$null | Out-Null } catch {}
                $m = [regex]::Match((& arp.exe -a $ip 2>$null | Out-String), '([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}')
                if ($m.Success) { $mac = $m.Value.Replace('-', ':').ToLower() }
            }
            if ($type -eq 'network') { $script:NetPrinters += @(, @($name, $ip, $mac)) }
            $d = 'false'; if ($pr.Default) { $d = 'true' }; if ($NoDefault) { $d = 'null' }
            # state: offline_mode = "Use printer offline" switched on; disconnected = spooler reports offline,
            # or a USB printer whose device isn't plugged in (no present USBPRINT device of the same vendor)
            # (Windows itself switches "Use printer offline" on when a USB printer is unplugged, so check presence first)
            $st = 'ok'; $gone = $false
            if ($port -match '^USB') {
                $vendor = (([string]$pr.DriverName) -split '\s+')[0]; if (-not $vendor) { $vendor = ($name -split '\s+')[0] }
                $here = $false; foreach ($u in $usbNow) { if ($vendor -and $u -like ('*' + $vendor + '*')) { $here = $true } }
                $gone = -not $here
            }
            if ($gone) { $st = 'disconnected' }
            elseif ($pr.WorkOffline) { $st = 'offline_mode' }
            elseif ([int]$pr.PrinterStatus -eq 7 -or [int]$pr.ExtendedPrinterStatus -eq 7) { $st = 'disconnected' }
            $items += ('{"name":' + (JStr $name) + ',"type":"' + $type + '","ip":' + (JStr $ip) + ',"mac":' + (JStr $mac) + ',"default":' + $d + ',"state":"' + $st + '"}')
        }
    } catch {}
    return ('[' + ($items -join ',') + ']')
}
# scanners (PnP class "Image" = WIA scanners; cameras skipped) -> JSON array string like printers.
# Network (WSD/eSCL) scanners get IP/MAC from a network printer with a matching name (usually the same MFP).
# Call after Get-PrintersJson.
function Get-ScannersJson {
    $items = @(); $seen = @{}
    try {
        foreach ($d in @(Get-WmiObject Win32_PnPEntity -Filter "ClassGuid='{6bdd1fc6-810f-11d0-bec7-08002be2092f}'")) {
            $name = ([string]$d.Name).Trim(); $id = [string]$d.DeviceID
            if (-not $name -or $seen.ContainsKey($name) -or $name -match 'Camera|Webcam|Cam\b|Kamera|\u041a\u0430\u043c\u0435\u0440' -or $id -match '^ROOT\\') { continue }
            $seen[$name] = 1
            $type = 'other'
            if ($id -match '^USB\\|^USBPRINT\\') { $type = 'usb' } elseif ($id -match '^SWD\\|WSD|^UMB\\|ESCL|^NETWORK') { $type = 'network' }
            $ip = ''; $mac = ''
            if ($type -eq 'network') {
                $w = @(($name -replace '[^\w\s-]', ' ').Split(' ', [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_.Length -ge 3 } | Select-Object -First 3)
                foreach ($p in $script:NetPrinters) {
                    $hit = 0; foreach ($x in $w) { if ($p[0] -match [regex]::Escape($x)) { $hit++ } }
                    if ($w.Count -gt 0 -and $hit -ge [math]::Min(2, $w.Count)) { $ip = $p[1]; $mac = $p[2]; break }
                }
            }
            # present device: ConfigManagerErrorCode 0 = working, anything else (22 = disabled, driver error) = problem
            $st = 'ok'; if ([int]$d.ConfigManagerErrorCode -ne 0) { $st = 'problem' }
            $items += ('{"name":' + (JStr $name) + ',"type":"' + $type + '","ip":' + (JStr $ip) + ',"mac":' + (JStr $mac) + ',"default":false,"state":"' + $st + '"}')
        }
        # installed but not plugged in now (Windows 8+: Get-PnpDevice also lists non-present devices)
        if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
            foreach ($d in @(Get-PnpDevice -Class Image -ErrorAction SilentlyContinue | Where-Object { -not $_.Present })) {
                $name = ([string]$d.FriendlyName).Trim(); $id = [string]$d.InstanceId
                if (-not $name -or $seen.ContainsKey($name) -or $name -match 'Camera|Webcam|Cam\b|Kamera|\u041a\u0430\u043c\u0435\u0440' -or $id -match '^ROOT\\') { continue }
                $seen[$name] = 1
                $type = 'other'; if ($id -match '^USB\\|^USBPRINT\\') { $type = 'usb' } elseif ($id -match '^SWD\\|WSD|^UMB\\|ESCL|^NETWORK') { $type = 'network' }
                $items += ('{"name":' + (JStr $name) + ',"type":"' + $type + '","ip":"","mac":"","default":false,"state":"disconnected"}')
            }
        }
    } catch {}
    return ('[' + ($items -join ',') + ']')
}
function HwJson($h, $keys = @('cpu', 'gpu', 'ram', 'disk', 'nic_type', 'nic_mbps', 'nic_name', 'mac', 'local_ip', 'users', 'logged_user', 'act_status', 'act_channel', 'act_kms', 'act_grace', 'office_name', 'office_status', 'office_channel', 'office_kms', 'office_detail', 'gpu_mem', 'board_vendor', 'board_name', 'cpu_cores', 'cpu_threads', 'ram_type', 'bt_name', 'bt_state')) {
    $o = ''
    foreach ($k in $keys) { $o += (',"' + $k + '":' + (JStr ([string]$h[$k]))) }
    return $o
}
# periodic refresh (at startup and every 12 h) so the panel notices hardware changes; needs admin rights
function Install-HwTask([string]$base) {
    try {
        $dir = Join-Path $env:ProgramData 'RustDeskNETH'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $f = Join-Path $dir 'hw.ps1'
        $wc = New-Object Net.WebClient
        try { $wc.DownloadFile($base + '/hw.ps1', $f) } catch {
            $x = New-Object -ComObject 'Msxml2.XMLHTTP'; $x.open('GET', $base + '/hw.ps1', $false); $x.send()
            if ($x.status -ne 200) { return $false }; [IO.File]::WriteAllText($f, [string]$x.responseText)
        }
        $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $f + '" -Task'
        & schtasks.exe /Create /F /RU SYSTEM /RL HIGHEST /TN 'RustDeskNETH\hw-startup' /SC ONSTART /DELAY 0003:00 /TR $cmd 2>$null | Out-Null
        & schtasks.exe /Create /F /RU SYSTEM /RL HIGHEST /TN 'RustDeskNETH\hw-12h' /SC HOURLY /MO 12 /TR $cmd 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        # commands from the panel (update RustDesk, shutdown, reboot): every minute, very light request
        & schtasks.exe /Create /F /RU SYSTEM /RL HIGHEST /TN 'RustDeskNETH\poll' /SC MINUTE /MO 1 /TR ($cmd.Replace(' -Task', ' -Poll')) 2>$null | Out-Null
        return ($ok -and $LASTEXITCODE -eq 0)
    } catch { return $false }
}
