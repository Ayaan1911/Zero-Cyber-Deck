# ZERO CyberSec Deck - Windows companion (PowerShell 5.1+). ASCII only on purpose.
# Nothing runs automatically. Network actions use the same Python scope gate as the Kali dashboard.
#   powershell -NoProfile -File .\Start-ZeroDeck.ps1          interactive menu
#   powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check   non-interactive dependency check (exit 1 on any problem)
param([switch]$Check)
$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
$LocalScope = Join-Path $Root 'config\scope.local.txt'   # untracked file wins: real targets stay out of git
$Scope = if (Test-Path -LiteralPath $LocalScope) { $LocalScope } else { Join-Path $Root 'config\scope.txt' }
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

function Test-LinkItem([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return [bool]($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
}

# True if the path or ANY existing ancestor folder is a link/junction/reparse point.
function Test-ChainHasLink([string]$Path) {
    $p = [System.IO.Path]::GetFullPath($Path)
    while ($p) {
        if ((Test-Path -LiteralPath $p) -and (Test-LinkItem $p)) { return $true }
        $parent = Split-Path -Parent $p
        if (-not $parent -or $parent -eq $p) { break }
        $p = $parent
    }
    return $false
}

# Returns $true only if the entry was written. Callers MUST stop when it returns $false (fail closed).
# The audit log is a plain text file: it records activity but does not prevent tampering.
function Write-Audit([string]$Action, [string]$Kind, [string]$Target, [string]$Verdict, [string]$Detail) {
    try {
        if (Test-ChainHasLink $AuditLog) { throw 'the audit log path (or a folder above it) is a link or junction' }
        $clean = { param($s) ($s -replace "[`t`r`n]", ' ') }
        $row = @((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $env:USERNAME, $Action, $Kind, (& $clean $Target), $Verdict, '-', (& $clean $Detail)) -join "`t"
        Add-Content -LiteralPath $AuditLog -Value $row -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch {
        Write-Host "AUDIT WRITE FAILED ($AuditLog): refusing to continue. $_" -ForegroundColor Red
        return $false
    }
}

# Unique, never-overwritten outputs.
function New-UniqueFile([string]$Dir, [string]$Stem, [string]$Ext) {
    for ($n = 0; $n -lt 1000; $n++) {
        $path = Join-Path $Dir $(if ($n -eq 0) { "$Stem$Ext" } else { "${Stem}_$n$Ext" })
        try { $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write); $fs.Close(); return $path }
        catch [System.IO.IOException] { continue }
    }
    throw 'cannot allocate a unique file name'
}
function New-UniqueDir([string]$Dir, [string]$Stem) {
    for ($n = 0; $n -lt 1000; $n++) {
        $path = Join-Path $Dir $(if ($n -eq 0) { $Stem } else { "${Stem}_$n" })
        try { [void](New-Item -ItemType Directory -Path $path -ErrorAction Stop); return $path } catch { continue }
    }
    throw 'cannot allocate a unique folder name'
}
function Get-Stamp { (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }

function Invoke-Guard([string[]]$Extra, [string]$Kind, [string]$Target, [string]$Action) {
    $out = & $Py $Guard @Extra '--audit' $AuditLog '--action' $Action $Scope $Kind '--' $Target
    if ($LASTEXITCODE -ne 0) { return $null }
    $d = @{}
    foreach ($line in @($out)) { if ($line -match '^(\w+)=(.*)$') { $d[$Matches[1]] = $Matches[2] } }
    if (-not $d.ContainsKey('host')) { return $null }
    return $d
}

# Two phases: (1) static pre-check, NO DNS  (2) operator types YES  (3) resolve + verify every answer is in scope.
# Returns a hashtable (host, addr, addrs, port, url) or $null.
function Invoke-Gate([string]$Kind, [string]$Target, [string]$Action) {
    if (-not $Py) { Write-Host 'Python 3.8+ is required for the scope gate (see SETUP.md).' -ForegroundColor Red; return $null }
    if ($Target -notmatch '^[\x21-\x7e]{1,2000}$' -or $Target.Contains('"')) {
        Write-Host 'Target contains unsupported characters (spaces, quotes or non-ASCII).' -ForegroundColor Red; return $null
    }
    Write-Host 'Only use on systems you own or have explicit written permission to test.' -ForegroundColor Yellow
    $pre = Invoke-Guard @('--no-resolve') $Kind $Target $Action
    if (-not $pre) { return $null }
    Write-Host "Pre-check passed (no DNS lookup made yet): $($pre['host'])"
    if ((Read-Host 'Confirm you are authorized for this exact target; this also authorizes a DNS lookup of a listed name (type YES)') -cne 'YES') {
        [void](Write-Audit $Action $Kind $pre['host'] 'CANCELLED' 'operator declined'); Write-Host 'Cancelled.'; return $null
    }
    if (-not (Write-Audit $Action $Kind $pre['host'] 'CONFIRMED' 'operator confirmed')) { return $null }
    $d = Invoke-Guard @() $Kind $Target $Action
    if ($d) { Write-Host "Verified target: $($d['host']) -> $($d['addrs'])" }
    return $d
}

function Save-Report([string]$Label, $Data) {
    $file = New-UniqueFile $Results "$(Get-Stamp)_$Label" '.txt'
    $Data | Out-File -Encoding UTF8 -FilePath $file
    $Data | Out-Host
    Write-Host "Saved to $file (UNENCRYPTED; treat as sensitive)" -ForegroundColor Yellow
}

function Invoke-Triage {
    if (-not (Write-Audit 'triage_windows' 'local' 'local' 'RUN' 'read-only triage')) { return }
    $dir = New-UniqueDir $Results "triage_$(Get-Stamp)"
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
    Write-Host "Read-only triage saved to $dir (sensitive; some items need an elevated shell for full detail)." -ForegroundColor Yellow
}

# Returns the number of problems found (0 = healthy). See docs/DEPENDENCIES.md.
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
    if ($Py -and (Test-Path -LiteralPath $Scope)) {
        $validation = (& $Py $Guard $Scope 'validate' 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { $bad++; $report += "[invalid] scope file $Scope : $validation" } else { $report += "[ok]      $validation" }
    }
    $report | Out-Host
    return $bad
}

if ($Check) {
    $problems = @(Test-Deck)[-1]
    if ($problems -gt 0) { exit 1 } else { exit 0 }
}

$invalid = 0
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
    if ($null -eq $choice) { Write-Host 'Input closed; exiting.'; break }   # EOF on redirected stdin must end the menu, never spin
    switch ($choice) {
        '1' {
            if (Write-Audit 'win_local_inventory' 'local' 'local' 'RUN' 'read-only inventory') {
                Save-Report 'win_local_inventory' @(
                    '=== Computer ===', (Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, CSName | Out-String),
                    '=== IP ===', (ipconfig /all | Out-String),
                    '=== Connections ===', (Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State | Format-Table | Out-String))
            }
        }
        '2' {
            $d = Invoke-Gate 'host' (Read-Host 'AUTHORIZED hostname or IP') 'win_dns'
            if ($d -and (Write-Audit 'win_dns' 'run' $d['host'] 'RUN' 'Resolve-DnsName')) {
                # Informational lookup; answers outside the verified set are flagged (DNS may have changed since verification).
                $answers = Resolve-DnsName -Name $d['host'] -Type A -ErrorAction Continue
                Save-Report 'win_dns' ($answers | Out-String)
                $verified = @($d['addrs'] -split ',')
                $drift = @($answers | Where-Object { $_.IPAddress -and ($verified -notcontains $_.IPAddress) } | ForEach-Object { $_.IPAddress })
                if ($drift.Count -gt 0) {
                    Write-Host "WARNING: DNS now returns unverified address(es): $($drift -join ', '). Do not test this name; re-run the gate." -ForegroundColor Red
                    [void](Write-Audit 'win_dns' 'run' $d['host'] 'DRIFT' "unverified answers: $($drift -join ',')")
                }
            }
        }
        '3' {
            $d = Invoke-Gate 'host' (Read-Host 'AUTHORIZED host or IP (single target)') 'win_traceroute'
            if ($d -and (Write-Audit 'win_traceroute' 'run' $d['host'] 'RUN' "tracert $($d['addr'])")) { Save-Report 'win_traceroute' (tracert -d -w 1000 -h 12 $d['addr'] | Out-String) }
        }
        '4' {
            $path = Read-Host 'Full path to local file'
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Host 'File not found.' }
            elseif (Write-Audit 'win_sha256' 'local' $path 'RUN' 'sha256 of a local file; writes a report') {   # audited BEFORE the report is written
                Save-Report 'win_sha256' (Get-FileHash -LiteralPath $path -Algorithm SHA256 | Format-List | Out-String)
            }
        }
        '5' {
            $dir = Read-Host 'Folder path'
            if (-not $Py) { Write-Host 'Python required.' }
            elseif (-not (Test-Path -LiteralPath $dir -PathType Container)) { Write-Host 'Folder not found.' }
            elseif ((Read-Host 'C = create manifest (never overwrites), V = verify existing MANIFEST.sha256') -ieq 'V') { & $Py $Evidence verify (Join-Path $dir 'MANIFEST.sha256') }
            elseif (Write-Audit 'win_manifest' 'local' $dir 'RUN' 'write MANIFEST.sha256') { & $Py $Evidence manifest $dir (Join-Path $dir 'MANIFEST.sha256') }
        }
        '6' { Invoke-Triage }
        '7' {
            if (-not $Py) { Write-Host 'Python required.' }
            elseif (Write-Audit 'win_report' 'local' 'local' 'RUN' 'markdown report') { & $Py $ReportPy --results $Results --scope $Scope --operator $env:USERNAME }
        }
        '8' { [void](Test-Deck) }
        '9' { $doc = Join-Path $Root 'SETUP.md'; if (Test-Path -LiteralPath $doc) { Get-Content -LiteralPath $doc | Select-Object -First 120 } }
        '0' { break }
        default {
            Write-Host 'Choose a listed number.'
            $invalid++
            if ($invalid -ge 5) { Write-Host 'Too many invalid choices (input closed?); exiting.'; $choice = '0' }
        }
    }
    if ($choice -in '1','2','3','4','5','6','7','8','9') { $invalid = 0 }
    if ($choice -ne '0') { [void](Read-Host 'Press Enter to continue') }
} while ($choice -ne '0')
