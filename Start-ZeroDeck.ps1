# PowerShell 5.1+ Windows companion. No scans, tools or downloads start automatically.
$ErrorActionPreference = 'Continue'
$Root = $PSScriptRoot
$Results = Join-Path $Root 'results'
New-Item -ItemType Directory -Force -Path $Results | Out-Null
function Save-Report([string]$Label, $Data) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $file = Join-Path $Results "${stamp}_${Label}.txt"
    $Data | Out-File -Encoding UTF8 -FilePath $file
    $Data | Out-Host
    Write-Host "Saved to $file (unencrypted)" -ForegroundColor Yellow
}
do {
    Write-Host "`n===========================================" -ForegroundColor Cyan
    Write-Host '       ZERO CYBERSEC DECK - WINDOWS'
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host '1  Local system and IP inventory'
    Write-Host '2  DNS query (read-only)'
    Write-Host '3  Traceroute (only authorized targets)'
    Write-Host '4  SHA-256 file hash'
    Write-Host '5  Show setup/boot instructions'
    Write-Host '0  Exit'
    $choice = Read-Host 'Choose'
    switch ($choice) {
        '1' {
            $report = @(
                '=== Computer ===', (Get-ComputerInfo | Select-Object CsName, WindowsProductName, OsVersion | Format-List | Out-String),
                '=== IP ===', (ipconfig /all | Out-String),
                '=== Connections ===', (Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State | Format-Table | Out-String)
            )
            Save-Report 'win_local_inventory' $report
        }
        '2' {
            $hostName = Read-Host 'Hostname (e.g., your authorized lab domain)'
            if ($hostName -match '^[a-zA-Z0-9.-]{1,253}$' -and -not $hostName.StartsWith('-')) {
                Save-Report 'win_dns' (Resolve-DnsName -Name $hostName -ErrorAction Continue | Out-String)
            } else { Write-Host 'Invalid hostname.' }
        }
        '3' {
            $hostName = Read-Host 'Authorized host/IP (single target)'
            if ($hostName -match '^[a-zA-Z0-9.-]{1,253}$' -and -not $hostName.StartsWith('-')) {
                $authorized = Read-Host 'Confirm you have explicit permission (type YES)'
                if ($authorized -ceq 'YES') { Save-Report 'win_traceroute' (tracert -d -w 1000 -h 12 $hostName | Out-String) }
            } else { Write-Host 'Invalid target.' }
        }
        '4' {
            $path = Read-Host 'Full path to local file'
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Save-Report 'win_sha256' (Get-FileHash -LiteralPath $path -Algorithm SHA256 | Format-List | Out-String)
            } else { Write-Host 'File not found.' }
        }
        '5' { Get-Content (Join-Path $Root 'SETUP.md') | Select-Object -First 80 }
        '0' { break }
        default { Write-Host 'Choose a listed number.' }
    }
    if ($choice -ne '0') { [void](Read-Host 'Press Enter to continue') }
} while ($choice -ne '0')
