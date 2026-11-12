# ZERO Deck USB deployment helper. COPY-ONLY: never formats, partitions, installs Ventoy or changes boot settings.
# Runs without administrator rights. ASCII only on purpose.
#   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     list what would be copied; writes nothing
#   .\Install-ZeroDeck.ps1 -DriveLetter E             copy + verify (asks you to type COPY)
#   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     refresh an existing ZERO-Deck folder (keeps your scope.txt, notes, results)
param(
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter,
    [switch]$DryRun,
    [switch]$Update,
    [switch]$AllowNonVentoyLabel
)
$ErrorActionPreference = 'Stop'
$Source = $PSScriptRoot

# Files that belong on the stick. Never copied: .git, results (except its README), caches, logs, ISO/images, captures.
function Get-DeckFiles([string]$Base) {
    $skipDir = '^(\.git|__pycache__|\.pytest_cache|node_modules)$'
    $skipExt = '^\.(iso|img|dat|vhd|vhdx|qcow2|pcap|pcapng|log|pyc)$'
    Get-ChildItem -LiteralPath $Base -Recurse -File -Force | Where-Object {
        $rel = $_.FullName.Substring($Base.Length).TrimStart('\', '/')
        $parts = $rel -split '[\\/]'
        $dirs = if ($parts.Length -gt 1) { $parts[0..($parts.Length - 2)] } else { @() }
        $inSkippedDir = @($dirs | Where-Object { $_ -match $skipDir }).Count -gt 0
        $inResults = ($parts[0] -eq 'results' -and $rel -ne 'results\README.md' -and $rel -ne 'results/README.md')
        -not $inSkippedDir -and -not $inResults -and $_.Extension -notmatch $skipExt
    }
}
# On -Update these user-owned files are never overwritten.
function Test-UserOwned([string]$Rel) { return ($Rel -replace '/', '\') -like 'config\scope.txt' -or ($Rel -replace '/', '\') -like 'notes\*' }

function Invoke-Deploy {
    if (-not $DriveLetter) { throw 'Specify -DriveLetter (the Ventoy data partition letter, e.g. E).' }
    $volume = Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop
    $disk = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop | Get-Disk
    if ($disk.BusType -ne 'USB') { throw "Refusing to copy: drive $DriveLetter is not detected as USB (BusType=$($disk.BusType))." }
    if ($Source.StartsWith("${DriveLetter}:", [StringComparison]::OrdinalIgnoreCase)) { throw 'Source and destination are on the same drive.' }
    if ($volume.FileSystemLabel -notmatch 'ventoy' -and -not $AllowNonVentoyLabel) {
        throw "Volume label is '$($volume.FileSystemLabel)', not Ventoy's default. If this is your Ventoy data partition, re-run with -AllowNonVentoyLabel."
    }
    $destination = "${DriveLetter}:\ZERO-Deck"
    if ((Test-Path -LiteralPath $destination) -and -not $Update) { throw "Destination exists: $destination. Use -Update to refresh it (your scope.txt, notes and results are kept)." }
    $files = @(Get-DeckFiles $Source)
    $bytes = ($files | Measure-Object Length -Sum).Sum
    if ($volume.SizeRemaining -lt ($bytes * 2)) { throw 'Not enough free space on the USB volume.' }
    Write-Host "Source:      $Source"
    Write-Host "Destination: $destination"
    Write-Host "USB disk:    $($disk.FriendlyName), $([math]::Round($disk.Size / 1GB, 1)) GiB, disk number $($disk.Number), label '$($volume.FileSystemLabel)', $($volume.FileSystem)"
    Write-Host "Files:       $($files.Count) ($([math]::Round($bytes / 1KB, 1)) KiB). results\, .git and caches are NOT copied."
    if ($DryRun) { $files | ForEach-Object { $_.FullName.Substring($Source.Length).TrimStart('\') } | Sort-Object | ForEach-Object { Write-Host "  would copy $_" }; Write-Host 'Dry run: nothing written.'; return }
    Write-Host 'This only copies files. It does NOT format the USB or install Ventoy.'
    if ((Read-Host 'Type COPY to continue') -cne 'COPY') { Write-Host 'Cancelled.'; return }
    $failed = 0
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($Source.Length).TrimStart('\')
        $target = Join-Path $destination $rel
        if ($Update -and (Test-Path -LiteralPath $target) -and (Test-UserOwned $rel)) { Write-Host "  kept     $rel"; continue }
        New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
        Copy-Item -LiteralPath $f.FullName -Destination $target -Force
        if ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) { Write-Host "  MISMATCH $rel" -ForegroundColor Red; $failed++ }
    }
    if ($failed -gt 0) { throw "$failed file(s) failed hash verification. Do not trust this copy; re-run after checking the USB." }
    Write-Host "Copied and hash-verified $($files.Count) file(s). Next: follow SETUP.md (Ventoy + ISOs are manual steps)." -ForegroundColor Green
}

# Dot-sourcing (for tests) defines the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Deploy }
