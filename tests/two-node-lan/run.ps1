[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LeftAdapter,
    [Parameter(Mandatory = $true)]
    [string]$RightAdapter,
    [string]$Python = 'python',
    [string]$Artifacts,
    [int]$ControllerPort = 44990,
    [int]$LeftUdpPort = 45101,
    [int]$RightUdpPort = 45102
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Require-Success([string]$Operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function Parse-KeyValue([string[]]$Lines) {
    $result = @{}
    foreach ($line in $Lines) {
        $pair = $line -split '=', 2
        if ($pair.Count -eq 2) {
            $result[$pair[0]] = $pair[1]
        }
    }
    return $result
}

function Add-AdvertisedEndpoint([string]$ConfigPath, [int]$Port) {
    $text = [IO.File]::ReadAllText($ConfigPath)
    $needle = "udp_bind = `"127.0.0.1:$Port`""
    $pattern = [regex]::new([regex]::Escape($needle) + '\r?\nadvertised_endpoints = \[\]')
    $endpoint = @"
$needle

[[transport.advertised_endpoints]]
address = "127.0.0.1:$Port"
priority = 0
max_datagram_size = 1200
"@
    if ($pattern.Matches($text).Count -ne 1) {
        throw "generated client configuration has an unexpected transport block"
    }
    [IO.File]::WriteAllText($ConfigPath, $pattern.Replace($text, $endpoint, 1), [Text.UTF8Encoding]::new($false))
}

function Wait-TcpPort([int]$Port, [Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            throw "controller exited before accepting connections"
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            $client.Dispose()
        }
    }
    throw "controller did not listen on 127.0.0.1:$Port"
}

function Wait-Log([string]$Path, [string]$Pattern, [Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            throw "process exited before log pattern '$Pattern'"
        }
        if ((Test-Path -LiteralPath $Path) -and (Select-String -LiteralPath $Path -SimpleMatch $Pattern -Quiet)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "timed out waiting for '$Pattern' in $Path"
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this end-to-end test from an elevated PowerShell session.'
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$server = Join-Path $repository 'target\release\stella-server.exe'
$client = Join-Path $repository 'target\release\stella-client.exe'
$verifier = Join-Path $PSScriptRoot 'verify_l2.py'
$requirements = Join-Path $PSScriptRoot 'requirements.txt'
if ([string]::IsNullOrWhiteSpace($Artifacts)) {
    $Artifacts = Join-Path $env:TEMP ("stella-two-node-" + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}
$Artifacts = [IO.Path]::GetFullPath($Artifacts)
if (Test-Path -LiteralPath $Artifacts) {
    throw "artifact directory already exists: $Artifacts"
}

$left = Get-NetAdapter -Name $LeftAdapter -ErrorAction Stop
$right = Get-NetAdapter -Name $RightAdapter -ErrorAction Stop
if ($left.InterfaceDescription -notlike 'TAP-Windows*' -or $right.InterfaceDescription -notlike 'TAP-Windows*') {
    throw 'Both selected adapters must be TAP-Windows adapters.'
}
if ($left.InterfaceGuid -eq $right.InterfaceGuid) {
    throw 'Left and right TAP adapters must be distinct devices.'
}

New-Item -ItemType Directory -Path $Artifacts | Out-Null
$serverConfig = Join-Path $Artifacts 'server\server.toml'
$leftConfig = Join-Path $Artifacts 'left\client.toml'
$rightConfig = Join-Path $Artifacts 'right\client.toml'
$scapy = Join-Path $Artifacts 'python-packages'
$serverProcess = $null
$leftProcess = $null
$rightProcess = $null

try {
    cargo build --manifest-path (Join-Path $repository 'Cargo.toml') --release -p stella-server -p stella-client
    Require-Success 'release build'

    $initLines = & $server --config $serverConfig init --listen "127.0.0.1:$ControllerPort" --tls-name localhost
    Require-Success 'controller initialization'
    $controller = Parse-KeyValue $initLines
    $networkId = (& $server --config $serverConfig network create --name 'Stella two-node LAN' --id '77777777777777777777777777777777').Trim()
    Require-Success 'network creation'
    $leftEnrollment = (& $server --config $serverConfig enrollment-token create).Trim()
    Require-Success 'left enrollment token creation'
    $rightEnrollment = (& $server --config $serverConfig enrollment-token create).Trim()
    Require-Success 'right enrollment token creation'
    $leftJoin = (& $server --config $serverConfig join-token create --network $networkId).Trim()
    Require-Success 'left join token creation'
    $rightJoin = (& $server --config $serverConfig join-token create --network $networkId).Trim()
    Require-Success 'right join token creation'

    & $client --config $leftConfig init --controller "127.0.0.1:$ControllerPort" --tls-name localhost --controller-id $controller.controller_id --spki-pin $controller.tls_spki_pin --display-name 'Stella Node A' --udp-bind "127.0.0.1:$LeftUdpPort"
    Require-Success 'left client initialization'
    & $client --config $rightConfig init --controller "127.0.0.1:$ControllerPort" --tls-name localhost --controller-id $controller.controller_id --spki-pin $controller.tls_spki_pin --display-name 'Stella Node B' --udp-bind "127.0.0.1:$RightUdpPort"
    Require-Success 'right client initialization'
    Add-AdvertisedEndpoint $leftConfig $LeftUdpPort
    Add-AdvertisedEndpoint $rightConfig $RightUdpPort

    $serverStdout = Join-Path $Artifacts 'server.stdout.log'
    $serverStderr = Join-Path $Artifacts 'server.stderr.log'
    $serverProcess = Start-Process -FilePath $server -ArgumentList @('--config', $serverConfig, 'run') -RedirectStandardOutput $serverStdout -RedirectStandardError $serverStderr -WindowStyle Hidden -PassThru
    Wait-TcpPort $ControllerPort $serverProcess

    & $client --config $leftConfig join --network $networkId --token $leftJoin --enrollment-token $leftEnrollment --tap-adapter $LeftAdapter
    Require-Success 'left client join'
    & $client --config $rightConfig join --network $networkId --token $rightJoin --enrollment-token $rightEnrollment --tap-adapter $RightAdapter
    Require-Success 'right client join'
    $leftEnrollment = $null
    $rightEnrollment = $null
    $leftJoin = $null
    $rightJoin = $null

    $leftStdout = Join-Path $Artifacts 'left.stdout.log'
    $leftStderr = Join-Path $Artifacts 'left.stderr.log'
    $rightStdout = Join-Path $Artifacts 'right.stdout.log'
    $rightStderr = Join-Path $Artifacts 'right.stderr.log'
    $leftProcess = Start-Process -FilePath $client -ArgumentList @('--config', $leftConfig, 'run') -RedirectStandardOutput $leftStdout -RedirectStandardError $leftStderr -WindowStyle Hidden -PassThru
    $rightProcess = Start-Process -FilePath $client -ArgumentList @('--config', $rightConfig, 'run') -RedirectStandardOutput $rightStdout -RedirectStandardError $rightStderr -WindowStyle Hidden -PassThru
    Wait-Log $leftStdout 'Windows data plane is active' $leftProcess
    Wait-Log $rightStdout 'Windows data plane is active' $rightProcess
    Start-Sleep -Seconds 2

    & $Python -m pip install --disable-pip-version-check --target $scapy -r $requirements
    Require-Success 'Scapy installation'
    $oldPythonPath = $env:PYTHONPATH
    $env:PYTHONPATH = $scapy
    try {
        $jsonReport = Join-Path $Artifacts 'l2-report.json'
        & $Python $verifier --left-interface $LeftAdapter --right-interface $RightAdapter --left-mac $left.MacAddress --right-mac $right.MacAddress --output $jsonReport
        Require-Success 'Layer-2 verification'
    } finally {
        $env:PYTHONPATH = $oldPythonPath
    }

    $report = Get-Content -Raw -LiteralPath (Join-Path $Artifacts 'l2-report.json') | ConvertFrom-Json
    $summary = @(
        '# Stella Windows two-node LAN verification',
        '',
        "- UTC: $([DateTime]::UtcNow.ToString('o'))",
        "- Git commit: $(git -C $repository rev-parse HEAD)",
        "- Left TAP: $LeftAdapter ($($left.MacAddress))",
        "- Right TAP: $RightAdapter ($($right.MacAddress))",
        "- Controller: 127.0.0.1:$ControllerPort",
        "- Result: $(if ($report.passed) { 'PASS' } else { 'FAIL' })",
        ''
    )
    foreach ($check in $report.checks) {
        $summary += "- $(if ($check.passed) { '[x]' } else { '[ ]' }) $($check.name): $($check.detail)"
    }
    [IO.File]::WriteAllLines((Join-Path $Artifacts 'summary.md'), $summary, [Text.UTF8Encoding]::new($false))
    Write-Output "PASS: artifacts=$Artifacts"
} finally {
    foreach ($process in @($leftProcess, $rightProcess, $serverProcess)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(5000) | Out-Null
        }
    }
}
