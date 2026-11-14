param(
    [string]$Distro = 'Ubuntu-24.04',
    [int]$Samples = 600,
    [int]$IntervalMilliseconds = 250,
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
if ($Samples -lt 2 -or $IntervalMilliseconds -lt 1) { throw 'Invalid sampling window' }
$probe = 'import json,time; print(json.dumps(dict(wall=time.time(),monotonic=time.monotonic(),raw=time.clock_gettime(time.CLOCK_MONOTONIC_RAW),boottime=time.clock_gettime(time.CLOCK_BOOTTIME))))'
$frequency = [double][System.Diagnostics.Stopwatch]::Frequency
$rows = @()
for ($index = 0; $index -lt $Samples; $index++) {
    $beforeUtc = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    $beforeMono = [System.Diagnostics.Stopwatch]::GetTimestamp() / $frequency
    $guestRaw = & wsl.exe -d $Distro --exec python3 -c $probe
    if ($LASTEXITCODE -ne 0) { throw 'Guest clock probe failed' }
    $afterMono = [System.Diagnostics.Stopwatch]::GetTimestamp() / $frequency
    $afterUtc = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    $rows += [pscustomobject]@{host_before=$beforeUtc; host_after=$afterUtc;
        host_before_monotonic=$beforeMono; host_after_monotonic=$afterMono;
        guest=($guestRaw | ConvertFrom-Json)}
    if ($index + 1 -lt $Samples) { Start-Sleep -Milliseconds $IntervalMilliseconds }
}
$first = $rows[0]; $last = $rows[-1]
$maximumStep = 0.0
for ($index = 1; $index -lt $rows.Count; $index++) {
    $previous = $rows[$index-1].guest; $current = $rows[$index].guest
    $step = [Math]::Abs(($current.wall-$previous.wall)-($current.monotonic-$previous.monotonic))
    $maximumStep = [Math]::Max($maximumStep, $step)
}
$hostElapsed = (($last.host_before_monotonic+$last.host_after_monotonic)-($first.host_before_monotonic+$first.host_after_monotonic))/2
$uncertainty = (($last.host_after_monotonic-$last.host_before_monotonic)+($first.host_after_monotonic-$first.host_before_monotonic))/2
$monoElapsed = $last.guest.monotonic-$first.guest.monotonic
$rawElapsed = $last.guest.raw-$first.guest.raw
$assessment = [pscustomobject]@{host_elapsed=$hostElapsed; guest_wall_elapsed=($last.guest.wall-$first.guest.wall);
    guest_monotonic_elapsed=$monoElapsed; guest_raw_elapsed=$rawElapsed; endpoint_uncertainty=$uncertainty;
    maximum_wall_monotonic_step=$maximumStep;
    screening_passed=($maximumStep -le 0.05 -and [Math]::Abs($monoElapsed-$hostElapsed) -le 0.1+$uncertainty -and [Math]::Abs($rawElapsed-$hostElapsed) -le 0.1+$uncertainty)}
$document = [pscustomobject]@{schema_version=1; purpose='Clock screening, not a replacement for original timing assertions';
    distro=$Distro; recorded_at=[DateTimeOffset]::UtcNow.ToString('o'); assessment=$assessment; samples=$rows}
$resolved = [System.IO.Path]::GetFullPath($Output)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolved)) | Out-Null
[System.IO.File]::WriteAllText($resolved, ($document | ConvertTo-Json -Depth 8))
$assessment | ConvertTo-Json
if (-not $assessment.screening_passed) { exit 1 }
