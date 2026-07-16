param(
    [string]$ConfigPath = "workdir/pref.toml",
    [int]$Port = 25597,
    [int]$Concurrency = 16,
    [double]$MaxPeakMiB = 0,
    [double]$MaxBinaryMiB = 0
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$executable = Join-Path $root "target/release/easysub-rs.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Release executable not found. Run 'cargo build --release' first."
}

$oldPort = $env:PORT
$env:PORT = $Port.ToString()
$process = $null
$client = $null
try {
    $process = Start-Process `
        -FilePath $executable `
        -ArgumentList $ConfigPath `
        -WorkingDirectory $root `
        -PassThru `
        -WindowStyle Hidden

    $ready = $false
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        try {
            $health = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/healthz" `
                -SkipHttpErrorCheck
            if ($health.StatusCode -eq 204) {
                $ready = $true
                break
            }
        } catch {
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        throw "Server did not become ready"
    }

    $node = [Uri]::EscapeDataString(
        "trojan://secret@example.com:443?sni=edge.example.com#edge"
    )
    $config = [Uri]::EscapeDataString("file:///ACL4SSR_Online_NoAuto.ini")
    $uri = "http://127.0.0.1:$Port/sub?target=clash&url=$node&config=$config"
    $client = [Net.Http.HttpClient]::new()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    [Threading.Tasks.Task[]]$tasks = 1..$Concurrency | ForEach-Object {
        $client.GetAsync($uri)
    }
    [Threading.Tasks.Task]::WaitAll($tasks)
    $responses = $tasks | ForEach-Object { $_.Result }
    $watch.Stop()

    $failed = @($responses | Where-Object { -not $_.IsSuccessStatusCode })
    if ($failed.Count -gt 0) {
        throw "$($failed.Count) benchmark requests failed"
    }
    $responseBytes = ($responses | ForEach-Object {
        $_.Content.Headers.ContentLength
    } | Measure-Object -Sum).Sum

    $process.Refresh()
    $peakMiB = $process.PeakWorkingSet64 / 1MB
    $workingMiB = $process.WorkingSet64 / 1MB
    $binaryMiB = (Get-Item -LiteralPath $executable).Length / 1MB
    [pscustomobject]@{
        Requests = $Concurrency
        WallSeconds = [math]::Round($watch.Elapsed.TotalSeconds, 3)
        ResponseMiB = [math]::Round($responseBytes / 1MB, 2)
        WorkingSetMiB = [math]::Round($workingMiB, 2)
        PeakWorkingSetMiB = [math]::Round($peakMiB, 2)
        BinaryMiB = [math]::Round($binaryMiB, 2)
    }

    if ($MaxPeakMiB -gt 0 -and $peakMiB -gt $MaxPeakMiB) {
        throw "Peak working set $peakMiB MiB exceeds $MaxPeakMiB MiB"
    }
    if ($MaxBinaryMiB -gt 0 -and $binaryMiB -gt $MaxBinaryMiB) {
        throw "Binary size $binaryMiB MiB exceeds $MaxBinaryMiB MiB"
    }

    foreach ($response in $responses) {
        $response.Dispose()
    }
} finally {
    if ($client) {
        $client.Dispose()
    }
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
    if ($null -eq $oldPort) {
        Remove-Item Env:PORT -ErrorAction SilentlyContinue
    } else {
        $env:PORT = $oldPort
    }
}
