<#
.SYNOPSIS
STools: interactive menu or unattended offline download.
.EXAMPLE
.\download-stools.ps1 -Datasets nvd,ghsa,news -Mode Updates -Period 7d -Output D:\STools -Lang ru -Quiet
#>
[CmdletBinding()]
param(
  [string[]]$Datasets = @(),
  [ValidateSet('Full','Updates')][string]$Mode,
  [ValidateSet('1d','7d','3m')][string]$Period,
  [string]$Output,
  [ValidateSet('ru','en')][string]$Lang,
  [switch]$Quiet,
  [switch]$NoProxy,
  [switch]$Help
)
$ErrorActionPreference = 'Stop'
$python = $null
$prefix = @()
foreach ($name in @('py','python3','python')) {
  $candidate = Get-Command $name -ErrorAction SilentlyContinue
  if (-not $candidate) { continue }
  if ($candidate.Source -match '[\\/]WindowsApps[\\/]python(?:3)?\.exe$') { continue }
  $tryPrefix = @()
  if ($name -eq 'py') { $tryPrefix = @('-3') }
  & $candidate.Source @tryPrefix -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>$null
  if ($LASTEXITCODE -eq 0) { $python = $candidate; $prefix = $tryPrefix; break }
}
if (-not $python) { [Console]::Error.WriteLine('Нужен Python 3.11+ / Python 3.11+ is required.'); exit 1 }
$arguments = @((Join-Path $PSScriptRoot 'offline_download.py'))
if ($Datasets.Count) { $arguments += @('--datasets', ($Datasets -join ',')) }
if ($Mode) { $arguments += @('--mode', $Mode.ToLowerInvariant()) }
if ($Period) { $arguments += @('--period', $Period) }
if ($Output) { $arguments += @('--output', $Output) }
if ($Lang) { $arguments += @('--lang', $Lang) }
if ($Quiet) { $arguments += '--quiet' }
if ($NoProxy) { $arguments += '--no-proxy' }
if ($Help) { $arguments += '--help' }
$previousPowerShell = $env:STOOLS_POWERSHELL
try {
  $env:STOOLS_POWERSHELL = (Get-Process -Id $PID).Path
  & $python.Source @prefix @arguments
  $result = $LASTEXITCODE
} finally {
  $env:STOOLS_POWERSHELL = $previousPowerShell
}
exit $result
