# ZERO CyberSec Deck - Windows companion (PowerShell 5.1+). ASCII only on purpose.
# Nothing runs automatically. Network actions use the same Python scope gate as the Kali dashboard.
#   powershell -NoProfile -File .\Start-ZeroDeck.ps1          interactive menu
#   powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check   non-interactive dependency check
param([switch]$Check)
$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
$Scope = Join-Path $Root 'config\scope.txt'
$Results = Join-Path $Root 'results'
$Guard = Join-Path $Root 'scripts\scope_guard.py'
$Evidence = Join-Path $Root 'scripts\evidence.py'
$ReportPy = Join-Path $Root 'scripts\report.py'
$AuditLog = Join-Path $Results 'audit.log'
New-Item -ItemType Directory -Force -Path $Results | Out-Null

function Find-Python {
    foreach ($name in 'python', 'python3', 'py') {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        & $cmd.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) { return $cmd.Source }
    }
    return $null
}
$Py = Find-Python

function Write-Audit([string]$Action, [string]$Kind, [string]$Target, [string]$Verdict, [string]$Detail) {
    $clean = { param($s) ($s -replace "[`t`r`n]", ' ') }
    $row = @((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $env:USERNAME, $Action, $Kind, (& $clean $Target), $Verdict, '-', (& $clean $Detail)) -join "`t"
    Add-Content -LiteralPath $AuditLog -Value $row -Encoding UTF8
}

# Returns a hashtable (host, addr, port, url) after scope validation + YES confirmation, or $null.
function Invoke-Gate([string]$Kind, [string]$Target, [string]$Action) {
    if (-not $Py) { Write-Host 'Python 3.8+ is required for the scope gate (see SETUP.md).' -ForegroundColor Red; return $null }
    if ($Target -notmatch '^[\x21-\x7e]{1,2000}$' -or $Target.Contains('"')) {
        Write-Host 'Target contains unsupported characters (spaces, quotes or non-ASCII).' -ForegroundColor Red; return $null
    }
    Write-Host 'Only use on systems you own or have explicit written permission to test.' -ForegroundColor Yellow
    $out = & $Py $Guard '--audit' $AuditLog '--action' $Action $Scope $Kind '--' $Target
    if ($LASTEXITCODE -ne 0) { return $null }
    $d = @{}
    foreach ($line in @($out)) { if ($line -match '^(\w+)=(.*)$') { $d[$Matches[1]] = $Matches[2] } }
    if (-not $d.ContainsKey('host')) { return $null }
    Write-Host "Verified target: $($d['host']) -> $($d['addr'])"
    if ((Read-Host 'Confirm you are authorized for this exact target (type YES)') -cne 'YES') {
        Write-Audit $Action $Kind $d['host'] 'CANCELLED' 'operator declined'; Write-Host 'Cancelled.'; return $null
    }
    Write-Audit $Action $Kind $d['host'] 'CONFIRMED' 'operator confirmed'
    return $d
}

function Save-Report([string]$Label, $Data) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $file = Join-Path $Results "${stamp}_${Label}.txt"
    $Data | Out-File -Encoding UTF8 -FilePath $file
    $Data | Out-Host
    Write-Host "Saved to $file (UNENCRYPTED; treat as sensitive)" -ForegroundColor Yellow
}

function Invoke-Triage {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $dir = Join-Path $Results "triage_$stamp"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $sections = [ordered]@{
        'system.txt'      = { Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, LastBootUpTime, CSName }
        'users.txt'       = { Get-LocalUser | Format-Table Name, Enabled, LastLogon -AutoSize; Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass -AutoSize }
        'processes.txt'   = { Get-Process | Sort-Object ProcessName | Format-Table Id, ProcessName, Path -AutoSize }
        'network.txt'     = { Get-NetIPAddress | Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize; Get-NetTCPConnection | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -AutoSize }
        'persistence.txt' = { Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location -AutoSize; Get-ScheduledTask | Where-Object State -ne 'Disabled' | Format-Table TaskName, TaskPath, State -AutoSize; Get-Service | Where-Object Status -eq 'Running' | Format-Table Name, DisplayName -AutoSize }
    }
    foreach ($name in $sections.Keys) {
        try { & $sections[$name] | Out-String -Width 250 | Out-File -Encoding UTF8 -FilePath (Join-Path $dir $name) }
        catch { "error collecting ${name}: $_" | Out-File -Encoding UTF8 -FilePath (Join-Path $dir $name) }
    }
    if ($Py) { & $Py $Evidence manifest $dir (Join-Path $dir 'MANIFEST.sha256') }
    Write-Audit 'triage_windows' 'local' 'local' 'RUN' "triage saved to $dir"
    Write-Host "Read-only triage saved to $dir (sensitive; some items need an elevated shell for full detail)." -ForegroundColor Yellow
}

function Test-Deck {
    $bad = 0
    $report = @()
    if ($Py) { $report += "[ok]      python    $Py" } else { $report += '[missing] python    install Python 3.8+ (python.org) - needed for the scope gate'; $bad++ }
    foreach ($f in $Guard, $Evidence, $ReportPy, $Scope) {
        if (Test-Path -LiteralPath $f) { $report += "[ok]      $(Split-Path $f -Leaf)" } else { $report += "[missing] $f"; $bad++ }
    }
    foreach ($t in 'nmap', 'wireshark', 'tshark') {
        if (Get-Command $t -ErrorAction SilentlyContinue) { $report += "[ok]      $t" } else { $report += "[absent]  $t (optional on Windows)" }
    }
    if ($Py -and (Test-Path -LiteralPath $Scope)) { $report += (& $Py $Guard $Scope 'validate' 2>&1 | Out-String).Trim() }
    $report | Out-Host
    return $bad
}

if ($Check) {
    $problems = @(Test-Deck)[-1]
    if ($problems -gt 0) { exit 1 } else { exit 0 }
}

do {
    Write-Host "`n===========================================" -ForegroundColor Cyan
    Write-Host '       ZERO CYBERSEC DECK - WINDOWS'
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host '1  Local system and IP inventory'
    Write-Host '2  DNS query (scope + resolution gated)'
    Write-Host '3  Traceroute (scope gated, verified address)'
    Write-Host '4  SHA-256 of a file'
    Write-Host '5  Create / verify a hash manifest for a folder'
    Write-Host '6  Local triage snapshot (read-only, hashed)'
    Write-Host '7  Generate Markdown session report'
    Write-Host '8  Dependency check'
    Write-Host '9  Show deployment / setup guide'
    Write-Host '0  Exit'
    $choice = Read-Host 'Choose'
    switch ($choice) {
        '1' {
            Save-Report 'win_local_inventory' @(
                '=== Computer ===', (Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, CSName | Out-String),
                '=== IP ===', (ipconfig /all | Out-String),
                '=== Connections ===', (Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State | Format-Table | Out-String))
            Write-Audit 'win_local_inventory' 'local' 'local' 'RUN' 'read-only inventory'
        }
        '2' {
            $d = Invoke-Gate 'host' (Read-Host 'AUTHORIZED hostname or IP') 'win_dns'
            if ($d) { Write-Audit 'win_dns' 'run' $d['host'] 'RUN' 'Resolve-DnsName'; Save-Report 'win_dns' (Resolve-DnsName -Name $d['host'] -Type A -ErrorAction Continue | Out-String) }
        }
        '3' {
            $d = Invoke-Gate 'host' (Read-Host 'AUTHORIZED host or IP (single target)') 'win_traceroute'
            if ($d) { Write-Audit 'win_traceroute' 'run' $d['host'] 'RUN' "tracert $($d['addr'])"; Save-Report 'win_traceroute' (tracert -d -w 1000 -h 12 $d['addr'] | Out-String) }
        }
        '4' {
            $path = Read-Host 'Full path to local file'
            if (Test-Path -LiteralPath $path -PathType Leaf) { Save-Report 'win_sha256' (Get-FileHash -LiteralPath $path -Algorithm SHA256 | Format-List | Out-String) }
            else { Write-Host 'File not found.' }
        }
        '5' {
            $dir = Read-Host 'Folder path'
            if (-not $Py) { Write-Host 'Python required.' }
            elseif (-not (Test-Path -LiteralPath $dir -PathType Container)) { Write-Host 'Folder not found.' }
            elseif ((Read-Host 'C = create manifest, V = verify existing MANIFEST.sha256') -ieq 'V') { & $Py $Evidence verify (Join-Path $dir 'MANIFEST.sha256') }
            else { & $Py $Evidence manifest $dir (Join-Path $dir 'MANIFEST.sha256') }
        }
        '6' { Invoke-Triage }
        '7' {
            if ($Py) { & $Py $ReportPy --results $Results --scope $Scope --operator $env:USERNAME } else { Write-Host 'Python required.' }
        }
        '8' { [void](Test-Deck) }
        '9' { $doc = Join-Path $Root 'SETUP.md'; if (Test-Path -LiteralPath $doc) { Get-Content -LiteralPath $doc | Select-Object -First 120 } }
        '0' { break }
        default { Write-Host 'Choose a listed number.' }
    }
    if ($choice -ne '0') { [void](Read-Host 'Press Enter to continue') }
} while ($choice -ne '0')
