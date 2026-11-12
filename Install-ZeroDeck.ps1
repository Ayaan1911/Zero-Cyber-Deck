# ZERO Deck USB deployment helper (application folder ONLY). Never formats, partitions, installs Ventoy or changes boot settings.
# Runs without administrator rights. ASCII only on purpose.
#   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     verify the release and show the plan; writes nothing
#   .\Install-ZeroDeck.ps1 -DriveLetter E             first install (asks you to type COPY)
#   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     replace the application with this release; the old one is kept
#
# ARCHITECTURE (read before changing this file):
#   E:\ZERO-Deck   application code only, exactly the files listed in SHA256SUMS.txt. Replaceable. Verified against that manifest.
#   E:\ZERO-DATA   YOUR results, notes, evidence, scope and audit log. THIS SCRIPT NEVER READS, COPIES, MOVES, DELETES OR REPLACES ANYTHING IN IT.
#                  It only (a) checks the format marker for compatibility BEFORE activating and (b) creates the folder if it does not exist at all.
#   An update therefore carries NO user data anywhere: stage the new release, verify, rename old -> ZERO-Deck.bak-<time>,
#   rename stage -> ZERO-Deck, verify again. The old application folder is kept for manual recovery. Nothing is ever deleted.
#   Old layouts that kept data INSIDE ZERO-Deck are detected and refused until you copy that data with scripts\migrate_data.py (see SETUP.md).
#
# LIMITS: folder renames are not an atomic transaction; exFAT has no journal. A crash between the two renames leaves
# ZERO-Deck.bak-<time> and no ZERO-Deck: rename the .bak folder back. Your data is not involved either way.
param(
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter,
    [switch]$DryRun,
    [switch]$Update,
    [switch]$AllowNonVentoyLabel,
    [switch]$AcknowledgeLegacyData
)
$ErrorActionPreference = 'Stop'
$Source = $PSScriptRoot

# Fault-injection hooks: step name (or "step:N" for the Nth occurrence) -> scriptblock. Tests set this to simulate failures
# (throw) or concurrent changes. Empty in production; nothing reads it from the environment or arguments.
$TestHooks = @{}
$HookCounts = @{}
function Test-Hook([string]$Step) {
    if ($script:TestHooks.Count -eq 0) { return }
    $script:HookCounts[$Step] = 1 + [int]$script:HookCounts[$Step]
    foreach ($key in $Step, ("{0}:{1}" -f $Step, $script:HookCounts[$Step])) {
        if ($script:TestHooks.ContainsKey($key)) { & $script:TestHooks[$key] }
    }
}

function Test-LinkItem([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return [bool]($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
}
function Get-FileSha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

# A manifest path is untrusted text: forward-slash relative path, no '.', '..', drive letters, streams, device names.
function Test-SafeRel([string]$Rel) {
    if (-not $Rel -or $Rel.StartsWith('/') -or $Rel.Contains('\') -or $Rel.Contains(':') -or $Rel -match '[\x00-\x1f<>"|?*]') { return $false }
    foreach ($seg in $Rel.Split('/')) {
        if (-not $seg -or $seg -eq '.' -or $seg -eq '..' -or $seg.EndsWith('.') -or $seg.EndsWith(' ')) { return $false }
        if ($seg -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') { return $false }
    }
    return $true
}

# Reads <root>\SHA256SUMS.txt into an ordered map rel -> sha256 (lowercase). Throws on anything malformed or unsafe.
function Read-ReleaseManifest([string]$Root) {
    $mf = Join-Path $Root 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $mf -PathType Leaf)) { throw "Release manifest not found: $mf" }
    if (Test-LinkItem $mf) { throw "Release manifest is a link/junction: $mf" }
    $map = [ordered]@{}
    $n = 0
    foreach ($line in [System.IO.File]::ReadAllLines($mf)) {
        $n++
        if (-not $line.Trim()) { continue }
        if ($line -notmatch '^([0-9a-f]{64}) [ *](.+)$') { throw "SHA256SUMS.txt line $n is malformed" }
        $rel = $Matches[2]
        if (-not (Test-SafeRel $rel)) { throw "SHA256SUMS.txt line $n has an unsafe path: $rel" }
        if ($map.Contains($rel)) { throw "SHA256SUMS.txt lists '$rel' twice" }
        $map[$rel] = $Matches[1]
    }
    if ($map.Count -eq 0) { throw 'SHA256SUMS.txt is empty' }
    return $map
}

# No component between $Root and the file may be a link/junction (the root itself is checked too).
function Assert-NoLinksOnPath([string]$Root, [string]$Rel) {
    $cur = $Root
    if (Test-LinkItem $cur) { throw "Link/junction in the path: $cur" }
    foreach ($part in $Rel.Split('/')) {
        $cur = Join-Path $cur $part
        if (Test-LinkItem $cur) { throw "Link/junction in the path: $cur" }
    }
}

# Content addressing is the defence against a substituted file: whatever is read must hash to the manifest value.
function Assert-TreeMatchesManifest([string]$Root, $Manifest, [string]$What) {
    foreach ($rel in $Manifest.Keys) {
        Assert-NoLinksOnPath $Root $rel
        $full = Join-Path $Root ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$What is missing '$rel'" }
        if ((Get-FileSha $full) -ne $Manifest[$rel]) { throw "$What differs from the release manifest: '$rel'" }
    }
}

function Get-RelFiles([string]$Root) {
    $base = $Root.TrimEnd('\', '/')
    $list = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($base)
    while ($stack.Count -gt 0) {
        foreach ($item in Get-ChildItem -LiteralPath $stack.Pop() -Force) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Link/junction found inside the tree: $($item.FullName)" }
            if ($item.PSIsContainer) { $stack.Push($item.FullName) } else { $list.Add($item.FullName.Substring($base.Length).TrimStart('\', '/').Replace('\', '/')) }
        }
    }
    return $list.ToArray()
}

# ---- data folder: COMPATIBILITY CHECK ONLY (never reads user files) -------------------------------------------------------
function Get-RequiredDataFormat([string]$Root) {
    $f = Join-Path $Root 'DATA_FORMAT'
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "Release has no DATA_FORMAT file: $f" }
    return [int]([System.IO.File]::ReadAllText($f).Trim())
}
function Get-DataState([string]$Data, [int]$Required) {
    if (-not (Test-Path -LiteralPath $Data)) { return [pscustomobject]@{ State = 'missing'; Message = "Data folder will be created: $Data" } }
    if (Test-LinkItem $Data) { throw "Data folder is a link/junction, refusing: $Data" }
    $marker = Join-Path $Data '.zerodeck-data'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { return [pscustomobject]@{ State = 'unmarked'; Message = "$Data exists but is not a ZERO data folder; it is left untouched and the deck will refuse to use it until you initialize or choose another folder." } }
    if (Test-LinkItem $marker) { throw "Data marker is a link: $marker" }
    $fmt = 0
    foreach ($line in [System.IO.File]::ReadAllLines($marker)) { if ($line -match '^format=(\d+)$') { $fmt = [int]$Matches[1] } }
    if ($fmt -gt $Required) { throw "Data folder uses format $fmt but this release understands up to $Required. Refusing to activate: update to a newer release instead." }
    return [pscustomobject]@{ State = 'ok'; Message = "Data folder $Data (format $fmt, release needs $Required)" }
}
function Initialize-DataDir([string]$Data, [int]$Required) {
    # only when the folder does not exist AT ALL; an existing folder is never touched
    if (Test-Path -LiteralPath $Data) { return $false }
    [void](New-Item -ItemType Directory -Path $Data)
    foreach ($sub in 'results', 'notes', 'config', 'evidence', 'archives', 'migrations') { [void](New-Item -ItemType Directory -Path (Join-Path $Data $sub)) }
    [System.IO.File]::WriteAllText((Join-Path $Data '.zerodeck-data'), ("format={0}`ncreated={1}`n" -f $Required, (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), (New-Object System.Text.UTF8Encoding($false)))
    return $true
}

# Old layouts kept operator files INSIDE the application folder. Detect (names only; contents are never read or copied).
function Get-LegacyDataFindings([string]$OldApp) {
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($dir in 'results', 'notes') {
        $p = Join-Path $OldApp $dir
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if (Test-LinkItem $p) { $found.Add("$dir (is a link/junction)"); continue }
        foreach ($f in Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue) { if ($f.Name -ne 'README.md') { $found.Add("$dir\$($f.FullName.Substring($p.TrimEnd('\').Length).TrimStart('\'))") } }
    }
    $cfg = Join-Path $OldApp 'config'
    if (Test-Path -LiteralPath $cfg) {
        if (Test-LinkItem $cfg) { $found.Add('config (is a link/junction)') }
        else {
            if (Test-Path -LiteralPath (Join-Path $cfg 'scope.local.txt')) { $found.Add('config\scope.local.txt') }
            $sc = Join-Path $cfg 'scope.txt'
            if ((Test-Path -LiteralPath $sc -PathType Leaf) -and -not (Test-LinkItem $sc)) {
                if (@([System.IO.File]::ReadAllLines($sc) | Where-Object { ($_ -replace '#.*$', '').Trim() }).Count -gt 0) { $found.Add('config\scope.txt (contains scope entries)') }
            }
        }
    }
    return $found.ToArray()
}

# Undo the renames only (never deletes). Throws a manual-recovery message if even that fails.
function Undo-Commit($State, [string]$Destination, [string]$Backup, [string]$Failed, [string]$Leaf) {
    try {
        if ($State.NewInPlace) {
            Test-Hook 'rollback-aside'
            Rename-Item -LiteralPath $Destination -NewName (Split-Path $Failed -Leaf)
            $State.NewInPlace = $false
            $State.NewAt = $Failed
        }
        if ($State.BackupRenamed) {
            Test-Hook 'rollback-restore'
            Rename-Item -LiteralPath $Backup -NewName $Leaf
            $State.BackupRenamed = $false
        }
    } catch {
        $where = if ($State.BackupRenamed) { "Your ORIGINAL application folder is intact at: $Backup  (rename it back to '$Leaf' in $(Split-Path $Destination -Parent))." } else { "Your original application folder is at: $Destination." }
        $new = if ($State.NewAt) { " The new, unverified tree is at: $($State.NewAt)." } else { '' }
        throw "MANUAL RECOVERY REQUIRED. NO DATA WAS DELETED (your data folder was never touched). Rollback step failed: $($_.Exception.Message) $where$new Do not delete anything until you have checked both folders."
    }
}

# Core logic, independent of USB checks so it can be tested against disposable folders.
function Deploy-DeckFiles {
    param([string]$SourceRoot, [string]$Destination, [string]$DataDir, [switch]$UpdateMode, [switch]$AcknowledgeLegacy, [string]$StagingName)
    $script:HookCounts = @{}
    # ---- preflight: no writes at all ------------------------------------------------------------------------------
    $parent = Split-Path $Destination -Parent
    $leaf = Split-Path $Destination -Leaf
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Parent folder not found: $parent" }
    if (Test-LinkItem $parent) { throw "Parent folder is a link/junction: $parent" }
    $destExists = Test-Path -LiteralPath $Destination
    if ($destExists -and (Test-LinkItem $Destination)) { throw "Destination is a link/junction, refusing: $Destination" }
    if ($destExists -and -not $UpdateMode) { throw "Destination exists: $Destination. Use -Update to replace the application (the old one is kept; your data folder is not touched)." }
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $staging = Join-Path $parent $(if ($StagingName) { $StagingName } else { "$leaf.staging-$stamp" })
    $backup = Join-Path $parent "$leaf.bak-$stamp"
    $failed = Join-Path $parent "$leaf.failed-$stamp"
    foreach ($p in $staging, $backup, $failed) { if (Test-Path -LiteralPath $p) { throw "Path already exists, not touching it: $p" } }
    $manifest = Read-ReleaseManifest $SourceRoot
    Assert-TreeMatchesManifest $SourceRoot $manifest 'The release folder you are installing from'
    $required = Get-RequiredDataFormat $SourceRoot
    $dataState = if ($DataDir) { Get-DataState $DataDir $required } else { [pscustomobject]@{ State = 'none'; Message = 'no data folder given' } }
    if ($destExists) {
        $legacy = @(Get-LegacyDataFindings $Destination)
        if ($legacy.Count -gt 0 -and -not $AcknowledgeLegacy) {
            throw ("The existing application folder still contains operator data in the OLD layout ($($legacy.Count) item(s), e.g. '$($legacy[0])'). It would NOT be carried over: it would stay in the .bak folder and the new release would not see it. " +
                   "Copy it first: python scripts\migrate_data.py --from `"$Destination`" --to `"$DataDir`"  (back up first; see SETUP.md), or re-run with -AcknowledgeLegacyData to proceed anyway.")
        }
    }
    $needed = [long]0
    foreach ($rel in $manifest.Keys) { $needed += (Get-Item -LiteralPath (Join-Path $SourceRoot ($rel -replace '/', '\'))).Length }
    $root = [System.IO.Path]::GetPathRoot($parent)
    if ($root) { if ((New-Object System.IO.DriveInfo($root)).AvailableFreeSpace -lt ($needed * 1.2)) { throw 'Not enough free space on the destination volume.' } }

    $state = [pscustomobject]@{ BackupRenamed = $false; NewInPlace = $false; NewAt = $null }
    try {
        # ---- stage: exactly the manifest files + the manifest ---------------------------------------------------------------
        Test-Hook 'stage-create'
        [void](New-Item -ItemType Directory -Path $staging)
        foreach ($rel in (@($manifest.Keys) + 'SHA256SUMS.txt')) {
            $from = Join-Path $SourceRoot ($rel -replace '/', '\')
            $to = Join-Path $staging ($rel -replace '/', '\')
            [void](New-Item -ItemType Directory -Force -Path (Split-Path $to -Parent))
            Copy-Item -LiteralPath $from -Destination $to
            if ($rel -ne 'SHA256SUMS.txt' -and (Get-FileSha $to) -ne $manifest[$rel]) { throw "Staged file differs from the release manifest: $rel" }
            Test-Hook 'stage-copy'
        }
        if ((Get-FileSha (Join-Path $staging 'SHA256SUMS.txt')) -ne (Get-FileSha (Join-Path $SourceRoot 'SHA256SUMS.txt'))) { throw 'Staged manifest differs from the source manifest.' }
        $want = @($manifest.Keys) + 'SHA256SUMS.txt' | Sort-Object
        $have = @(Get-RelFiles $staging) | Sort-Object
        if (($want -join "`n") -ne ($have -join "`n")) { throw 'The staged tree is not exactly the release (extra or missing files).' }
        Test-Hook 'stage-verify'
        # ---- compatibility re-check immediately before activation ------------------------------------------------------------
        Test-Hook 'pre-commit-verify'
        if ($DataDir) { [void](Get-DataState $DataDir $required) }
        if ($destExists -and -not $AcknowledgeLegacy -and @(Get-LegacyDataFindings $Destination).Count -gt 0) { throw 'Operator data appeared inside the old application folder while the update was running. Close the deck and start again.' }
        # ---- commit with renames only -----------------------------------------------------------------------------------------------
        if ($destExists) {
            Test-Hook 'before-backup-rename'
            Rename-Item -LiteralPath $Destination -NewName (Split-Path $backup -Leaf)
            $state.BackupRenamed = $true
            Test-Hook 'after-backup-rename'
        }
        Rename-Item -LiteralPath $staging -NewName $leaf
        $state.NewInPlace = $true
        Test-Hook 'after-commit-rename'
        Assert-TreeMatchesManifest $Destination $manifest 'The installed application'
        $wantInstalled = (@($manifest.Keys) + 'SHA256SUMS.txt' | Sort-Object) -join "`n"
        $haveInstalled = (@(Get-RelFiles $Destination) | Sort-Object) -join "`n"
        if ($wantInstalled -ne $haveInstalled) { throw 'The installed tree is not exactly the release.' }
        Test-Hook 'post-verify'
    } catch {
        $reason = $_.Exception.Message
        if (-not ($state.BackupRenamed -or $state.NewInPlace)) {
            throw "UPDATE ABORTED, NOTHING CHANGED: the existing application folder '$Destination' was not modified and your data folder was never touched. Reason: $reason  Leftover staging folder (inspect, then delete it yourself): $staging"
        }
        Undo-Commit $state $Destination $backup $failed $leaf
        $restored = if ($destExists) { "the original application folder is back at '$Destination'" } else { 'there was no previous install, so nothing is installed' }
        throw "UPDATE ROLLED BACK, NOTHING DELETED: $restored. Reason: $reason  The unverified new tree was kept at: $failed"
    }
    # ---- data folder: created only if it does not exist at all; failure here never undoes a verified activation ------------
    $dataCreated = $false
    $dataNote = $dataState.Message
    if ($DataDir -and $dataState.State -eq 'missing') {
        try { Test-Hook 'data-init'; $dataCreated = Initialize-DataDir $DataDir $required; $dataNote = "Created data folder $DataDir" }
        catch { $dataNote = "The application is installed, but the data folder could not be created ($($_.Exception.Message)). Create it with: bash zero-deck.sh --init-data" }
    }
    return [pscustomobject]@{ Destination = $Destination; Backup = $(if ($destExists) { $backup } else { $null }); FileCount = $manifest.Count + 1; DataDir = $DataDir; DataState = $dataState.State; DataCreated = $dataCreated; DataNote = $dataNote }
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
    $dataDir = "${DriveLetter}:\ZERO-DATA"
    $manifest = Read-ReleaseManifest $Source
    Assert-TreeMatchesManifest $Source $manifest 'The release folder you are installing from'
    $required = Get-RequiredDataFormat $Source
    $dataState = Get-DataState $dataDir $required
    $bytes = 0
    foreach ($rel in $manifest.Keys) { $bytes += (Get-Item -LiteralPath (Join-Path $Source ($rel -replace '/', '\'))).Length }
    if ($volume.SizeRemaining -lt ($bytes * 1.5)) { throw 'Not enough free space on the USB volume.' }
    Write-Host "Source:        $Source  (verified against SHA256SUMS.txt: $($manifest.Count) files)"
    Write-Host "Application:   $destination$(if (Test-Path -LiteralPath $destination) { '  (exists: -Update required; the old copy is kept as ZERO-Deck.bak-<time>)' })"
    Write-Host "Data folder:   $dataDir  - $($dataState.Message). It is never modified by this script."
    Write-Host "USB disk:      $($disk.FriendlyName), $([math]::Round($disk.Size / 1GB, 1)) GiB, disk number $($disk.Number), label '$($volume.FileSystemLabel)', $($volume.FileSystem)"
    if (Test-Path -LiteralPath $destination) {
        $legacy = @(Get-LegacyDataFindings $destination)
        if ($legacy.Count -gt 0) { Write-Host "LEGACY DATA inside the old application folder ($($legacy.Count) item(s)): it will NOT be carried over. Migrate it first (SETUP.md) or pass -AcknowledgeLegacyData." -ForegroundColor Yellow }
    }
    if ($DryRun) {
        $manifest.Keys | Sort-Object | ForEach-Object { Write-Host "  would copy $_" }
        Write-Host 'Dry run: nothing written.'
        return
    }
    Write-Host 'This only copies the application. It does NOT format the USB, install Ventoy, or touch your data. Nothing is ever deleted.'
    if ((Read-Host 'Type COPY to continue') -cne 'COPY') { Write-Host 'Cancelled.'; return }
    $result = Deploy-DeckFiles -SourceRoot $Source -Destination $destination -DataDir $dataDir -UpdateMode:$Update -AcknowledgeLegacy:$AcknowledgeLegacyData
    Write-Host "Installed and verified $($result.FileCount) file(s) against the release manifest at $($result.Destination)." -ForegroundColor Green
    Write-Host $result.DataNote
    if ($result.Backup) { Write-Host "Previous application kept, untouched, at $($result.Backup). Delete it yourself once you have checked the new one." }
    Write-Host 'Next: follow SETUP.md (Ventoy + ISOs are manual steps).'
}

# Dot-sourcing (for tests) defines the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Deploy }
