[CmdletBinding()]
param(
    [string]$Adapter = 'Local Area Connection',
    [string]$Python = 'python',
    [string]$Artifacts,
    [int]$ControllerPort = 44990,
    [int]$LeftUdpPort = 45101,
    [int]$RightUdpPort = 45102,
    [int]$PeerControlPort = 45200
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

function Enable-DiagnosticLogging([string]$ConfigPath) {
    $text = [IO.File]::ReadAllText($ConfigPath)
    $configured = 'filter = "info,stella_client=info"'
    if (-not $text.Contains($configured)) {
        throw 'generated client configuration has an unexpected logging filter'
    }
    [IO.File]::WriteAllText(
        $ConfigPath,
        $text.Replace($configured, 'filter = "info,stella_client=debug"'),
        [Text.UTF8Encoding]::new($false)
    )
}

function Wait-TcpPort([int]$Port, [Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            throw 'controller exited before accepting connections'
        }
        $socket = [Net.Sockets.TcpClient]::new()
        try {
            $socket.Connect('127.0.0.1', $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            $socket.Dispose()
        }
    }
    throw "controller did not listen on 127.0.0.1:$Port"
}

function Wait-Log([string]$Path, [string]$Pattern, [Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            $diagnostic = if (Test-Path -LiteralPath $Path) { [IO.File]::ReadAllText($Path) } else { '' }
            throw "process exited before log pattern '$Pattern': $diagnostic"
        }
        if ((Test-Path -LiteralPath $Path) -and (Select-String -LiteralPath $Path -SimpleMatch $Pattern -Quiet)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "timed out waiting for '$Pattern' in $Path"
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$server = Join-Path $repository 'target\release\stella-server.exe'
$client = Join-Path $repository 'target\release\stella-client.exe'
$peer = Join-Path $repository 'target\release\examples\l2_test_peer.exe'
$verifier = Join-Path $PSScriptRoot 'verify_one_tap.py'
$requirements = Join-Path $PSScriptRoot 'requirements.txt'
if ([string]::IsNullOrWhiteSpace($Artifacts)) {
    $Artifacts = Join-Path $env:TEMP ("stella-one-tap-" + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}
$Artifacts = [IO.Path]::GetFullPath($Artifacts)
if (Test-Path -LiteralPath $Artifacts) {
    throw "artifact directory already exists: $Artifacts"
}

$tap = Get-NetAdapter -Name $Adapter -ErrorAction Stop
if ($tap.InterfaceDescription -notlike 'TAP-Windows*') {
    throw "$Adapter is not a TAP-Windows adapter"
}
$mtus = @(Get-NetIPInterface -InterfaceAlias $Adapter -ErrorAction Stop |
    Select-Object -ExpandProperty NlMtu -Unique)
if ($mtus.Count -ne 1) {
    throw "$Adapter must have one matching IPv4/IPv6 MTU for non-elevated verification"
}
$installedMtu = [int]$mtus[0]
$leftMac = $tap.MacAddress
$rightMac = '02-53-54-45-4C-42'

New-Item -ItemType Directory -Path $Artifacts | Out-Null
$serverConfig = Join-Path $Artifacts 'server\server.toml'
$leftConfig = Join-Path $Artifacts 'left\client.toml'
$rightConfig = Join-Path $Artifacts 'right\client.toml'
$scapy = Join-Path $Artifacts 'python-packages'
$serverProcess = $null
$leftProcess = $null
$peerProcess = $null

try {
    cargo build --release -p stella-server -p stella-client
    Require-Success 'release application build'
    cargo build --release -p stella-client --example l2_test_peer
    Require-Success 'headless peer build'

    $initLines = & $server --config $serverConfig init --listen "127.0.0.1:$ControllerPort" --tls-name localhost
    Require-Success 'controller initialization'
    $controller = Parse-KeyValue $initLines
    $networkId = (& $server --config $serverConfig network create --name 'Stella one-TAP verification LAN' --id '77777777777777777777777777777777').Trim()
    Require-Success 'network creation'
    $leftEnrollment = (& $server --config $serverConfig enrollment-token create).Trim()
    Require-Success 'left enrollment token creation'
    $rightEnrollment = (& $server --config $serverConfig enrollment-token create).Trim()
    Require-Success 'right enrollment token creation'
    $leftJoin = (& $server --config $serverConfig join-token create --network $networkId).Trim()
    Require-Success 'left join token creation'
    $rightJoin = (& $server --config $serverConfig join-token create --network $networkId).Trim()
    Require-Success 'right join token creation'

    & $client --config $leftConfig init --controller "127.0.0.1:$ControllerPort" --tls-name localhost --controller-id $controller.controller_id --spki-pin $controller.tls_spki_pin --display-name 'Stella Windows TAP node' --udp-bind "127.0.0.1:$LeftUdpPort"
    Require-Success 'left client initialization'
    & $client --config $rightConfig init --controller "127.0.0.1:$ControllerPort" --tls-name localhost --controller-id $controller.controller_id --spki-pin $controller.tls_spki_pin --display-name 'Stella headless verification node' --udp-bind "127.0.0.1:$RightUdpPort"
    Require-Success 'right client initialization'
    Add-AdvertisedEndpoint $leftConfig $LeftUdpPort
    Add-AdvertisedEndpoint $rightConfig $RightUdpPort
    Enable-DiagnosticLogging $leftConfig

    $serverStdout = Join-Path $Artifacts 'server.stdout.log'
    $serverStderr = Join-Path $Artifacts 'server.stderr.log'
    $serverProcess = Start-Process -FilePath $server -ArgumentList @('--config', $serverConfig, 'run') -RedirectStandardOutput $serverStdout -RedirectStandardError $serverStderr -WindowStyle Hidden -PassThru
    Wait-TcpPort $ControllerPort $serverProcess

    & $client --config $leftConfig join --network $networkId --token $leftJoin --enrollment-token $leftEnrollment --tap-adapter $Adapter
    Require-Success 'left client join'
    & $client --config $rightConfig join --network $networkId --token $rightJoin --enrollment-token $rightEnrollment --tap-adapter 'Headless verification peer'
    Require-Success 'right peer join'
    $leftEnrollment = $null
    $rightEnrollment = $null
    $leftJoin = $null
    $rightJoin = $null

    $leftStdout = Join-Path $Artifacts 'left.stdout.log'
    $leftStderr = Join-Path $Artifacts 'left.stderr.log'
    $peerStdout = Join-Path $Artifacts 'peer.stdout.log'
    $peerStderr = Join-Path $Artifacts 'peer.stderr.log'
    $leftProcess = Start-Process -FilePath $client -ArgumentList @('--config', $leftConfig, 'run') -RedirectStandardOutput $leftStdout -RedirectStandardError $leftStderr -WindowStyle Hidden -PassThru
    Wait-Log $leftStdout 'Windows data plane is active' $leftProcess
    $peerProcess = Start-Process -FilePath $peer -ArgumentList @('--config', $rightConfig, '--mac', $rightMac, '--control', "127.0.0.1:$PeerControlPort") -RedirectStandardOutput $peerStdout -RedirectStandardError $peerStderr -WindowStyle Hidden -PassThru
    Wait-Log $peerStderr 'headless verifier control is listening' $peerProcess

    & $Python -m pip install --disable-pip-version-check --target $scapy -r $requirements
    Require-Success 'Scapy installation'
    $oldPythonPath = $env:PYTHONPATH
    $env:PYTHONPATH = $scapy
    try {
        $jsonReport = Join-Path $Artifacts 'l2-report.json'
        & $Python $verifier --interface $Adapter --left-mac $leftMac --right-mac $rightMac --peer-control "127.0.0.1:$PeerControlPort" --output $jsonReport
        Require-Success 'Layer-2 verification'
    } finally {
        $env:PYTHONPATH = $oldPythonPath
    }

    $report = Get-Content -Raw -LiteralPath (Join-Path $Artifacts 'l2-report.json') | ConvertFrom-Json
    $summary = @(
        '# Stella Windows one-TAP two-node verification',
        '',
        "- UTC: $([DateTime]::UtcNow.ToString('o'))",
        "- Git commit: $(git -C $repository rev-parse HEAD)",
        "- Windows TAP node: $Adapter ($leftMac)",
        "- Headless Stella peer: $rightMac",
        "- Windows TAP IP MTU: $installedMtu bytes",
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
    foreach ($process in @($leftProcess, $peerProcess, $serverProcess)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(5000) | Out-Null
        }
    }
}
