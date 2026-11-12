# ZERO Deck USB deployment helper. COPY-ONLY: never formats, partitions, installs Ventoy or changes boot settings.
# Runs without administrator rights. ASCII only on purpose.
#   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     list what would be copied; writes nothing
#   .\Install-ZeroDeck.ps1 -DriveLetter E             stage + verify + install (asks you to type COPY)
#   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     replace an existing install; your results, notes and scope files are carried over
#
# DATA-PRESERVATION MODEL (read before changing this file):
#   * NOTHING IS EVER DELETED and user data is NEVER MOVED. The old install is only ever renamed.
#   * Phase 1 (stage): the new tree is copied into ZERO-Deck.staging-<time> and every file is hash-verified.
#   * Phase 2 (carry over): your results, notes and scope files are COPIED from the old install into the stage and
#     hash-verified; the old install is not touched. The old install is re-checked just before commit and the update is
#     aborted if it changed.
#   * Phase 3 (commit): two directory renames - old -> ZERO-Deck.bak-<time>, stage -> ZERO-Deck. Then everything is verified again.
#   * Any failure before the first rename changes nothing. After it, the renames are undone (also non-destructively:
#     a bad new tree is renamed to ZERO-Deck.failed-<time>, never removed). If even the undo fails, the script stops and
#     prints exact manual-recovery instructions. Leftover staging/failed/bak folders are yours to inspect and delete.
#   * Windows directory renames are not transactional: a crash or power loss between the two renames leaves
#     ZERO-Deck.bak-<time> and no ZERO-Deck. Recovery: rename ZERO-Deck.bak-<time> back to ZERO-Deck. See SETUP.md.
param(
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter,
    [switch]$DryRun,
    [switch]$Update,
    [switch]$AllowNonVentoyLabel
)
$ErrorActionPreference = 'Stop'
$Source = $PSScriptRoot

# Fault-injection hooks: step name (or "step:N" for the Nth occurrence) -> scriptblock. Tests set this to simulate failures
# (throw) or concurrent changes. It is empty in production and nothing reads it from the environment or arguments.
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
function Get-FileSha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Get-RelPath([string]$Base, [string]$Full) { return $Full.Substring($Base.TrimEnd('\', '/').Length).TrimStart('\', '/') }

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
            $rel = Get-RelPath $Base $item.FullName
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

# The operator's own data inside an existing install. Any link/junction in it aborts the update (fail closed).
function Get-UserDataFiles([string]$Install) {
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($dir in 'results', 'notes') {
        $root = Join-Path $Install $dir
        if (-not (Test-Path -LiteralPath $root)) { continue }
        if (Test-LinkItem $root) { throw "User data folder is a link/junction, refusing to update: $root" }
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            foreach ($item in Get-ChildItem -LiteralPath $stack.Pop() -Force) {
                if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Link/junction inside user data, refusing to update: $($item.FullName)" }
                if ($item.PSIsContainer) { $stack.Push($item.FullName) }
                else { $found.Add([pscustomobject]@{ Rel = (Get-RelPath $Install $item.FullName); Full = $item.FullName; Kind = 'data' }) }
            }
        }
    }
    foreach ($name in 'scope.txt', 'scope.local.txt') {
        $p = Join-Path $Install "config\$name"
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if (Test-LinkItem $p) { throw "Scope file is a link, refusing to update: $p" }
        $found.Add([pscustomobject]@{ Rel = "config\$name"; Full = $p; Kind = 'scope' })
    }
    return $found.ToArray()
}

function Get-UserDataHashes($Files) {
    $map = @{}
    foreach ($u in $Files) { $map[$u.Rel] = Get-FileSha $u.Full }
    return $map
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
        $where = if ($State.BackupRenamed) { "Your ORIGINAL install is intact at: $Backup  (rename it back to '$Leaf' in $(Split-Path $Destination -Parent))." } else { "Your original install is at: $Destination." }
        $new = if ($State.NewAt) { " The new, unverified tree is at: $($State.NewAt)." } else { '' }
        throw "MANUAL RECOVERY REQUIRED. NO DATA WAS DELETED. Rollback step failed: $($_.Exception.Message) $where$new Do not delete anything until you have checked both folders."
    }
}

# Core logic, independent of USB checks so it can be tested against disposable folders.
function Deploy-DeckFiles {
    param([string]$SourceRoot, [string]$Destination, [switch]$UpdateMode, [string]$StagingName)
    $script:HookCounts = @{}
    # ---- preflight: no writes at all ------------------------------------------------------------------------------
    $parent = Split-Path $Destination -Parent
    $leaf = Split-Path $Destination -Leaf
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Parent folder not found: $parent" }
    if (Test-LinkItem $parent) { throw "Parent folder is a link/junction: $parent" }
    $destExists = Test-Path -LiteralPath $Destination
    if ($destExists -and (Test-LinkItem $Destination)) { throw "Destination is a link/junction, refusing: $Destination" }
    if ($destExists -and -not $UpdateMode) { throw "Destination exists: $Destination. Use -Update to replace it (a backup is kept; your results, notes and scope are carried over)." }
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $staging = Join-Path $parent $(if ($StagingName) { $StagingName } else { "$leaf.staging-$stamp" })
    $backup = Join-Path $parent "$leaf.bak-$stamp"
    $failed = Join-Path $parent "$leaf.failed-$stamp"
    foreach ($p in $staging, $backup, $failed) { if (Test-Path -LiteralPath $p) { throw "Path already exists, not touching it: $p" } }
    $userFiles = @()
    if ($destExists) { $userFiles = @(Get-UserDataFiles $Destination) }
    $userHash = Get-UserDataHashes $userFiles
    $files = @(Get-DeckFiles $SourceRoot)
    $needed = [long](($files | Measure-Object Length -Sum).Sum) + [long](($userFiles | ForEach-Object { (Get-Item -LiteralPath $_.Full).Length } | Measure-Object -Sum).Sum)
    $root = [System.IO.Path]::GetPathRoot($parent)
    if ($root) { if ((New-Object System.IO.DriveInfo($root)).AvailableFreeSpace -lt ($needed * 1.2)) { throw 'Not enough free space on the destination volume.' } }

    $state = [pscustomobject]@{ BackupRenamed = $false; NewInPlace = $false; NewAt = $null }
    $skipped = @{}
    try {
        # ---- phase 1: stage the new tree ---------------------------------------------------------------------------
        Test-Hook 'stage-create'
        [void](New-Item -ItemType Directory -Path $staging)
        foreach ($f in $files) {
            $rel = Get-RelPath $SourceRoot $f.FullName
            $target = Join-Path $staging $rel
            [void](New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent))
            Copy-Item -LiteralPath $f.FullName -Destination $target
            if ((Get-FileSha $f.FullName) -ne (Get-FileSha $target)) { throw "Hash mismatch while staging: $rel" }
            Test-Hook 'stage-copy'
        }
        if (@(Get-ChildItem -LiteralPath $staging -Recurse -File -Force).Count -ne $files.Count) { throw 'Staged file count does not match the source list.' }
        Test-Hook 'stage-verify'
        # ---- phase 2: COPY user data into the stage (the old install is not touched) --------------------------------------
        foreach ($u in $userFiles) {
            $target = Join-Path $staging $u.Rel
            if ($u.Kind -eq 'data' -and (Test-Path -LiteralPath $target)) { $skipped[$u.Rel] = $true; Test-Hook 'userdata-copy'; continue }   # new README wins; the old one stays in the backup
            [void](New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent))
            Copy-Item -LiteralPath $u.Full -Destination $target -Force   # -Force only replaces the staged scope TEMPLATE; the stage is ours
            if ((Get-FileSha $target) -ne $userHash[$u.Rel]) { throw "Hash mismatch while carrying over user data: $($u.Rel)" }
            Test-Hook 'userdata-copy'
        }
        foreach ($u in $userFiles) {
            if ($skipped.ContainsKey($u.Rel)) { continue }
            $target = Join-Path $staging $u.Rel
            if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or (Get-FileSha $target) -ne $userHash[$u.Rel]) { throw "User data missing or different in the stage: $($u.Rel)" }
        }
        Test-Hook 'userdata-verify'
        # ---- re-check that the old install did not change while we worked ---------------------------------------------------
        Test-Hook 'pre-commit-verify'
        if ($destExists) {
            $now = @(Get-UserDataFiles $Destination)
            $nowHash = Get-UserDataHashes $now
            $same = ($now.Count -eq $userFiles.Count)
            foreach ($key in $nowHash.Keys) { if (-not $userHash.ContainsKey($key) -or $userHash[$key] -ne $nowHash[$key]) { $same = $false } }
            if (-not $same) { throw 'The existing install changed while the update was running. Close anything using it and run the update again.' }
        }
        # ---- phase 3: commit with renames only -----------------------------------------------------------------------------
        if ($destExists) {
            Test-Hook 'before-backup-rename'
            Rename-Item -LiteralPath $Destination -NewName (Split-Path $backup -Leaf)
            $state.BackupRenamed = $true
            Test-Hook 'after-backup-rename'
        }
        Rename-Item -LiteralPath $staging -NewName $leaf
        $state.NewInPlace = $true
        Test-Hook 'after-commit-rename'
        foreach ($u in $userFiles) {
            if ($skipped.ContainsKey($u.Rel)) { continue }
            $final = Join-Path $Destination $u.Rel
            if (-not (Test-Path -LiteralPath $final -PathType Leaf) -or (Get-FileSha $final) -ne $userHash[$u.Rel]) { throw "Post-install verification failed for: $($u.Rel)" }
        }
        Test-Hook 'post-verify'
    } catch {
        $reason = $_.Exception.Message
        if (-not ($state.BackupRenamed -or $state.NewInPlace)) {
            throw "UPDATE ABORTED, NOTHING CHANGED: the existing install at '$Destination' was not modified. Reason: $reason  Leftover staging folder (inspect, then delete it yourself): $staging"
        }
        Undo-Commit $state $Destination $backup $failed $leaf
        $restored = if ($destExists) { "the original install is back at '$Destination'" } else { 'there was no previous install, so nothing is installed' }
        throw "UPDATE ROLLED BACK, NOTHING DELETED: $restored. Reason: $reason  The unverified new tree was kept at: $failed"
    }
    return [pscustomobject]@{ Destination = $Destination; Backup = $(if ($destExists) { $backup } else { $null }); FileCount = $files.Count; UserFileCount = $userFiles.Count }
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
    Write-Host "Destination: $destination$(if (Test-Path -LiteralPath $destination) { '  (exists: -Update required; the old copy is kept as ZERO-Deck.bak-<time>)' })"
    Write-Host "USB disk:    $($disk.FriendlyName), $([math]::Round($disk.Size / 1GB, 1)) GiB, disk number $($disk.Number), label '$($volume.FileSystemLabel)', $($volume.FileSystem)"
    Write-Host "Files:       $($files.Count) ($([math]::Round($bytes / 1KB, 1)) KiB). Links, results\ contents, .git and caches are NOT copied."
    if ($DryRun) {
        $files | ForEach-Object { $_.FullName.Substring($Source.Length).TrimStart('\') } | Sort-Object | ForEach-Object { Write-Host "  would copy $_" }
        Write-Host 'Dry run: nothing written.'
        return
    }
    Write-Host 'This only copies files. It does NOT format the USB or install Ventoy. Nothing is ever deleted.'
    if ((Read-Host 'Type COPY to continue') -cne 'COPY') { Write-Host 'Cancelled.'; return }
    $result = Deploy-DeckFiles -SourceRoot $Source -Destination $destination -UpdateMode:$Update
    Write-Host "Installed and hash-verified $($result.FileCount) file(s) (+ $($result.UserFileCount) of your own files carried over) at $($result.Destination)." -ForegroundColor Green
    if ($result.Backup) { Write-Host "Previous install kept, untouched, at $($result.Backup). Delete it yourself once you have checked the new one." }
    Write-Host 'Next: follow SETUP.md (Ventoy + ISOs are manual steps).'
}

# Dot-sourcing (for tests) defines the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Deploy }
