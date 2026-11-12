# Copy-only Windows installer; never formats drives or installs Ventoy.
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]$')][string]$DriveLetter)
$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$drive = Get-PSDrive -Name $DriveLetter -ErrorAction Stop
$disk = Get-Partition -DriveLetter $DriveLetter | Get-Disk
if ($disk.BusType -ne 'USB') { throw "Refusing to copy: drive $DriveLetter is not detected as USB (BusType=$($disk.BusType))." }
$destination = "$($DriveLetter):\ZERO-Deck"
if (Test-Path -LiteralPath $destination) { throw "Destination exists: $destination. Back it up and copy manually to update." }
Write-Host "Source: $source"
Write-Host "Destination: $destination"
Write-Host "USB disk: $($disk.FriendlyName), $([math]::Round($disk.Size/1GB,1)) GiB, disk number $($disk.Number)"
Write-Host 'This only copies files. It does NOT format the USB or install Ventoy.'
$answer = Read-Host 'Type COPY to continue'
if ($answer -cne 'COPY') { Write-Host 'Cancelled.'; exit }
New-Item -ItemType Directory -Path $destination | Out-Null
Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force
}
Write-Host 'Files copied. Follow SETUP.md to install Ventoy and add independently downloaded ISO files.'
