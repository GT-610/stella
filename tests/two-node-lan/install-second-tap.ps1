[CmdletBinding()]
param(
    [string]$ExistingAdapter = 'Local Area Connection',
    [string]$ExistingName = 'Stella Node A',
    [string]$NewName = 'Stella Node B',
    [string]$Release = '9.27.0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this adapter installation script from an elevated PowerShell session.'
}

$existing = Get-NetAdapter -Name $ExistingAdapter -ErrorAction Stop
if ($existing.InterfaceDescription -notlike 'TAP-Windows*') {
    throw "$ExistingAdapter is not a TAP-Windows adapter"
}
if (Get-NetAdapter -Name $NewName -ErrorAction SilentlyContinue) {
    throw "an adapter named $NewName already exists"
}

$downloadRoot = Join-Path $env:TEMP "stella-tap-windows-$Release"
$archive = Join-Path $downloadRoot 'dist.win10.zip'
$distribution = Join-Path $downloadRoot 'dist'
$amd64 = Join-Path $distribution 'dist.win10\amd64'
$devcon = Join-Path $amd64 'devcon.exe'
$inf = Join-Path $amd64 'OemVista.inf'
$driver = Join-Path $amd64 'tap0901.sys'
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $archive)) {
    $uri = "https://github.com/OpenVPN/tap-windows6/releases/download/$Release/dist.win10.zip"
    Invoke-WebRequest -Uri $uri -OutFile $archive
}
if (-not (Test-Path -LiteralPath $devcon)) {
    Expand-Archive -LiteralPath $archive -DestinationPath $distribution -Force
}

foreach ($path in @($devcon, $driver)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "invalid Authenticode signature for $path`: $($signature.StatusMessage)"
    }
}

$before = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like 'TAP-Windows*' } | ForEach-Object InterfaceGuid)
& $devcon install $inf 'root\tap0901'
if ($LASTEXITCODE -notin 0, 1) {
    throw "devcon failed with exit code $LASTEXITCODE"
}

$created = $null
$deadline = [DateTime]::UtcNow.AddSeconds(20)
while ([DateTime]::UtcNow -lt $deadline) {
    $created = Get-NetAdapter -IncludeHidden |
        Where-Object {
            $_.InterfaceDescription -like 'TAP-Windows*' -and
            $_.InterfaceGuid -notin $before
        } |
        Select-Object -First 1
    if ($null -ne $created) {
        break
    }
    Start-Sleep -Milliseconds 500
}
if ($null -eq $created) {
    throw 'TAP-Windows installation completed without a discoverable new adapter'
}

if ($existing.Name -ne $ExistingName) {
    Rename-NetAdapter -Name $existing.Name -NewName $ExistingName
}
Rename-NetAdapter -Name $created.Name -NewName $NewName

Get-NetAdapter -Name $ExistingName, $NewName |
    Sort-Object Name |
    Format-Table Name, InterfaceDescription, InterfaceGuid, MacAddress, Status, ifIndex -AutoSize
