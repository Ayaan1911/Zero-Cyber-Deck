# ZERO Deck USB deployment helper. COPY-ONLY: never formats, partitions, installs Ventoy or changes boot settings.
# Runs without administrator rights. ASCII only on purpose.
#   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     list what would be copied; writes nothing
#   .\Install-ZeroDeck.ps1 -DriveLetter E             stage + verify + install (asks you to type COPY)
#   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     replace an existing install; your results, notes and scope files are carried over
# Safety model: files are copied into ZERO-Deck.staging-<time> and hash-verified FIRST. Only a fully verified stage is
# swapped in (an existing install is renamed to ZERO-Deck.bak-<time>, never deleted). Any failure rolls back.
param(
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter,
    [switch]$DryRun,
    [switch]$Update,
    [switch]$AllowNonVentoyLabel
)
$ErrorActionPreference = 'Stop'
$Source = $PSScriptRoot

function Test-LinkItem([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return [bool]($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
}

# Files that belong on the stick. Never copied: links/junctions (skipped with a warning), .git, caches, logs,
# ISO/images/captures, and anything in results\ except its README.
function Get-DeckFiles([string]$Base) {
    $skipDir = '^(\.git|__pycache__|\.pytest_cache|node_modules)$'
    $skipExt = '^\.(iso|img|dat|vhd|vhdx|qcow2|pcap|pcapng|log|pyc)$'
    $files = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Base)
    while ($stack.Count -gt 0) {
        foreach ($item in Get-ChildItem -LiteralPath $stack.Pop() -Force) {
            $rel = $item.FullName.Substring($Base.Length).TrimStart('\', '/')
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { Write-Warning "Skipping link/junction (never followed): $rel"; continue }
            if ($item.PSIsContainer) {
                if ($item.Name -notmatch $skipDir -and $rel -notlike 'results\*' -and $rel -notlike 'results/*') { $stack.Push($item.FullName) }
            } elseif ($item.Extension -notmatch $skipExt -and ($rel -notlike 'results\*' -or $rel -eq 'results\README.md')) {
                $files.Add($item)
            }
        }
    }
    return $files.ToArray()
}

function Remove-OwnStaging([string]$Path) {
    # Only ever called on the unique staging folder this run created; it contains plain copied files, never links.
    if ((Test-Path -LiteralPath $Path) -and -not (Test-LinkItem $Path)) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

# Carry the operator's own data from the old install into the new one without overwriting anything new.
function Restore-UserData([string]$Old, [string]$New) {
    foreach ($dir in 'results', 'notes') {
        $oldDir = Join-Path $Old $dir
        if (-not (Test-Path -LiteralPath $oldDir -PathType Container) -or (Test-LinkItem $oldDir)) { continue }
        $newDir = Join-Path $New $dir
        [void](New-Item -ItemType Directory -Force -Path $newDir)
        foreach ($child in Get-ChildItem -LiteralPath $oldDir -Force) {
            if (Test-LinkItem $child.FullName) { Write-Warning "Left link in backup: $($child.FullName)"; continue }
            $to = Join-Path $newDir $child.Name
            if (-not (Test-Path -LiteralPath $to)) { Move-Item -LiteralPath $child.FullName -Destination $to }
        }
    }
    foreach ($name in 'scope.txt', 'scope.local.txt') {
        $oldScope = Join-Path $Old "config\$name"
        if ((Test-Path -LiteralPath $oldScope -PathType Leaf) -and -not (Test-LinkItem $oldScope)) {
            [void](New-Item -ItemType Directory -Force -Path (Join-Path $New 'config'))
            Copy-Item -LiteralPath $oldScope -Destination (Join-Path $New "config\$name") -Force
        }
    }
}

# Core copy logic, independent of any USB checks so it can be tested against temp folders.
function Deploy-DeckFiles {
    param([string]$SourceRoot, [string]$Destination, [switch]$UpdateMode, [string]$StagingName)
    $parent = Split-Path $Destination -Parent
    $leaf = Split-Path $Destination -Leaf
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Parent folder not found: $parent" }
    if (Test-LinkItem $parent) { throw "Parent folder is a link/junction: $parent" }
    $destExists = Test-Path -LiteralPath $Destination
    if ($destExists -and (Test-LinkItem $Destination)) { throw "Destination is a link/junction, refusing: $Destination" }
    if ($destExists -and -not $UpdateMode) { throw "Destination exists: $Destination. Use -Update to replace it (a backup is kept; your results, notes and scope are carried over)." }
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $staging = Join-Path $parent $(if ($StagingName) { $StagingName } else { "$leaf.staging-$stamp" })
    if (Test-Path -LiteralPath $staging) { throw "Staging path already exists, not touching it: $staging" }
    $files = @(Get-DeckFiles $SourceRoot)
    try {
        [void](New-Item -ItemType Directory -Path $staging)
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($SourceRoot.Length).TrimStart('\', '/')
            $target = Join-Path $staging $rel
            [void](New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent))
            Copy-Item -LiteralPath $f.FullName -Destination $target
            if ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) { throw "Hash mismatch while staging: $rel" }
        }
        if (@(Get-ChildItem -LiteralPath $staging -Recurse -File -Force).Count -ne $files.Count) { throw 'Staged file count does not match the source list.' }
    } catch {
        Remove-OwnStaging $staging
        throw
    }
    $backup = $null
    try {
        if ($destExists) {
            $backup = Join-Path $parent "$leaf.bak-$stamp"
            if (Test-Path -LiteralPath $backup) { throw "Backup path already exists: $backup" }
            Rename-Item -LiteralPath $Destination -NewName (Split-Path $backup -Leaf)
        }
        Rename-Item -LiteralPath $staging -NewName $leaf
        if ($backup) { Restore-UserData $backup $Destination }
    } catch {
        $failure = $_
        # Roll back: put any half-installed new tree aside, then restore the original install.
        if ($backup -and (Test-Path -LiteralPath $backup)) {
            if (Test-Path -LiteralPath $Destination) { Rename-Item -LiteralPath $Destination -NewName (Split-Path $staging -Leaf) }
            Rename-Item -LiteralPath $backup -NewName $leaf
        }
        Remove-OwnStaging $staging
        throw $failure
    }
    return [pscustomobject]@{ Destination = $Destination; Backup = $backup; FileCount = $files.Count }
}

# Wrapper so tests can replace the real disk queries.
function Get-UsbTarget([string]$Letter) {
    $volume = Get-Volume -DriveLetter $Letter -ErrorAction Stop
    $disk = Get-Partition -DriveLetter $Letter -ErrorAction Stop | Get-Disk
    return [pscustomobject]@{ Volume = $volume; Disk = $disk }
}

function Invoke-Deploy {
    if (-not $DriveLetter) { throw 'Specify -DriveLetter (the Ventoy data partition letter, e.g. E).' }
    $target = Get-UsbTarget $DriveLetter
    $volume = $target.Volume
    $disk = $target.Disk
    if ($disk.BusType -ne 'USB') { throw "Refusing to copy: drive $DriveLetter is not detected as USB (BusType=$($disk.BusType))." }
    if ($Source.StartsWith("${DriveLetter}:", [StringComparison]::OrdinalIgnoreCase)) { throw 'Source and destination are on the same drive.' }
    if ($volume.FileSystemLabel -notmatch 'ventoy' -and -not $AllowNonVentoyLabel) {
        throw "Volume label is '$($volume.FileSystemLabel)', not Ventoy's default. If this is your Ventoy data partition, re-run with -AllowNonVentoyLabel."
    }
    $destination = "${DriveLetter}:\ZERO-Deck"
    $files = @(Get-DeckFiles $Source)
    $bytes = ($files | Measure-Object Length -Sum).Sum
    if ($volume.SizeRemaining -lt ($bytes * 1.5)) { throw 'Not enough free space on the USB volume.' }
    Write-Host "Source:      $Source"
    Write-Host "Destination: $destination$(if (Test-Path -LiteralPath $destination) { '  (exists: -Update required; old copy is kept as ZERO-Deck.bak-<time>)' })"
    Write-Host "USB disk:    $($disk.FriendlyName), $([math]::Round($disk.Size / 1GB, 1)) GiB, disk number $($disk.Number), label '$($volume.FileSystemLabel)', $($volume.FileSystem)"
    Write-Host "Files:       $($files.Count) ($([math]::Round($bytes / 1KB, 1)) KiB). Links, results\, .git and caches are NOT copied."
    if ($DryRun) {
        $files | ForEach-Object { $_.FullName.Substring($Source.Length).TrimStart('\') } | Sort-Object | ForEach-Object { Write-Host "  would copy $_" }
        Write-Host 'Dry run: nothing written.'
        return
    }
    Write-Host 'This only copies files. It does NOT format the USB or install Ventoy.'
    if ((Read-Host 'Type COPY to continue') -cne 'COPY') { Write-Host 'Cancelled.'; return }
    $result = Deploy-DeckFiles -SourceRoot $Source -Destination $destination -UpdateMode:$Update
    Write-Host "Installed and hash-verified $($result.FileCount) file(s) at $($result.Destination)." -ForegroundColor Green
    if ($result.Backup) { Write-Host "Previous install kept at $($result.Backup). Delete it yourself once you have checked the new one." }
    Write-Host 'Next: follow SETUP.md (Ventoy + ISOs are manual steps).'
}

# Dot-sourcing (for tests) defines the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Deploy }
