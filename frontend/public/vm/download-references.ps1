<#
.SYNOPSIS
  Скачать справочники модуля VM STools одним архивом для сети без интернета.

.DESCRIPTION
  Качает EPSS, NVD (по годам), ExploitDB, Metasploit, размётку CTID ATT&CK и каталог CISA KEV
  и складывает их в один zip. Архив загружается в STools: «Настройки и данные → Справочники →
  Загрузить архив». Справочник узнаётся по имени файла, поэтому имена в архиве не меняйте.

  Прокси берётся из системы (настройки Windows текущего пользователя), вход на прокси — под
  учётной записью Windows. Проверка сертификатов не отключается: за прокси, который подменяет
  сертификаты, скачивание упадёт с понятной причиной.

  Запуск из консоли PowerShell:
    .\download-references.ps1
    .\download-references.ps1 -Years 2024,2025 -Skip msf
    .\download-references.ps1 -AllYears -Out D:\refs.zip
  Если политика запрещает скрипты: powershell -ExecutionPolicy Bypass -File .\download-references.ps1

.PARAMETER Out
  Путь к архиву. По умолчанию vm-references-ГГГГММДД.zip в текущей папке.
.PARAMETER Years
  Годы NVD: списком (2024,2025) или диапазоном (2022-2026). По умолчанию последние пять: архив укладывается в лимит загрузки (500 МБ).
.PARAMETER AllYears
  NVD за все годы, с 2002.
.PARAMETER Skip
  Какие справочники не качать: epss, nvd, exploitdb, msf, attack, kev.
.PARAMETER NoProxy
  Ходить напрямую, без прокси.
.PARAMETER ProxyCredential
  Спросить логин и пароль прокси, если вход под учётной записью Windows не проходит (HTTP 407).
  Учётные данные остаются только в памяти этого запуска.
#>
[CmdletBinding()]
param(
  [string]$Out = "",
  # Строки, а не числа: при запуске через -File «2024,2025» приходит одной строкой.
  [string[]]$Years = @(),
  [switch]$AllYears,
  [string[]]$Skip = @(),
  [switch]$NoProxy,
  [switch]$ProxyCredential,
  # Для тестов: справочник → адрес папки, где лежат файлы с теми же именами.
  [Parameter(DontShow = $true)][hashtable]$BaseUrls = @{}
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

$UserAgent = "STools-references/1"
$Retries = 3
$Known = @("epss", "nvd", "exploitdb", "msf", "attack", "kev")

function Split-List([string[]]$Values) {
  $list = @()
  foreach ($v in $Values) {
    foreach ($p in ($v -split "[,;\s]+")) { if ($p) { $list += $p } }
  }
  return $list
}

function Get-Years([string[]]$Values) {
  # «2024,2025», «2022-2026» и их смесь; прочее — понятная ошибка, а не исключение приведения типа.
  $list = @()
  foreach ($p in (Split-List $Values)) {
    if ($p -match '^(\d{4})-(\d{4})$') {
      $a = [int]$Matches[1]; $b = [int]$Matches[2]
      if ($a -gt $b) { Write-Host "в -Years диапазон наоборот: $p" -ForegroundColor Red; exit 1 }
      $list += @($a..$b)
    } elseif ($p -match '^\d{4}$') {
      $list += [int]$p
    } else {
      Write-Host "непонятный год в -Years: $p (пример: 2024,2025 или 2022-2026)" -ForegroundColor Red
      exit 1
    }
  }
  return $list
}

# Windows PowerShell 5.1 по умолчанию не предлагает TLS 1.2, а NVD и GitHub без него не отвечают.
# В PowerShell 7 набор протоколов задаёт система, его не сужаем.
if ($PSVersionTable.PSEdition -ne "Core") {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$skipList = @(Split-List $Skip | ForEach-Object { $_.ToLowerInvariant() })
foreach ($s in $skipList) {
  if ($Known -notcontains $s) {
    Write-Host "неизвестный справочник в -Skip: $s (есть: $($Known -join ', '))" -ForegroundColor Red
    exit 1
  }
}

$thisYear = (Get-Date).Year
if ($AllYears) {
  $yearList = @(2002..$thisYear)
} elseif ($Years.Count -gt 0) {
  $yearList = @(Get-Years $Years)
} else {
  $yearList = @(($thisYear - 4)..$thisYear)
}

if (-not $Out) { $Out = "vm-references-{0}.zip" -f (Get-Date -Format "yyyyMMdd") }
# Путь относительно текущей папки PowerShell, а не процесса .NET.
$Out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)

# Прокси: адрес и учётные записи не печатаются — только есть он или нет.
if ($NoProxy) {
  $Proxy = $null
  Write-Host "прокси: нет"
} else {
  $Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
  if ($ProxyCredential) {
    $cred = Get-Credential -Message "Учётные данные прокси"
    if (-not $cred) { Write-Host "учётные данные не введены" -ForegroundColor Red; exit 1 }
    $Proxy.Credentials = $cred.GetNetworkCredential()
  } else {
    $Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
  }
  Write-Host "прокси: системный"
}

# Ссылки — те же, что у кнопок «Скачать» в STools. Ссылка CTID закреплена за версией размётки.
$gh = "https://raw.githubusercontent.com"
$items = @(
  @{ Ref = "epss"; Name = "epss_scores-current.csv.gz"; Url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" }
)
foreach ($y in $yearList) {
  $items += @{ Ref = "nvd"; Name = "nvdcve-2.0-$y.json.gz"; Url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz" }
}
$items += @(
  @{ Ref = "exploitdb"; Name = "files_exploits.csv"; Url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" },
  @{ Ref = "msf"; Name = "modules_metadata_base.json"; Url = "$gh/rapid7/metasploit-framework/master/db/modules_metadata_base.json" },
  @{ Ref = "attack"; Name = "kev-07.28.2025_attack-16.1-enterprise.json"; Url = "$gh/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json" },
  # Имя с «&» сохраняется буквально: по нему сервер узнаёт справочник.
  @{ Ref = "attack"; Name = "Att&ckToCveMappings.csv"; Url = "$gh/center-for-threat-informed-defense/mappings-explorer/main/src/mapex_convert/mappings/Att%26ckToCveMappings.csv" },
  @{ Ref = "kev"; Name = "known_exploited_vulnerabilities.json"; Url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" }
)

function Save-Feed([string]$Url, [string]$Path) {
  # HttpWebRequest, а не Invoke-WebRequest: объект прокси с учётными данными Windows
  # принимает одинаково и 5.1, и 7; ответ пишется в файл потоком, без памяти на всю ленту.
  $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
  $req.Proxy = $Proxy
  $req.UserAgent = $UserAgent
  $req.Timeout = 60000
  # Простой дольше 2 минут — обрыв попытки; NVD отдаёт ленты медленно и с паузами.
  $req.ReadWriteTimeout = 120000
  # Докачка: если от прошлой попытки остался кусок, просим продолжение (Range); сервер,
  # который диапазоны не умеет, ответит 200 — тогда файл пишется заново.
  $have = 0
  if (Test-Path -LiteralPath $Path) { $have = (Get-Item -LiteralPath $Path).Length }
  if ($have -gt 0) { $req.AddRange([long]$have) }
  $resp = $req.GetResponse()
  try {
    $append = ($have -gt 0) -and ([int]$resp.StatusCode -eq 206)
    $src = $resp.GetResponseStream()
    try {
      if ($append) { $dst = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append) }
      else { $dst = [System.IO.File]::Create($Path) }
      try { $src.CopyTo($dst) } finally { $dst.Dispose() }
    } finally {
      $src.Dispose()
    }
  } finally {
    $resp.Dispose()
  }
}

function Find-WebException($Err) {
  $e = $Err.Exception
  while ($e -and -not ($e -is [System.Net.WebException])) { $e = $e.InnerException }
  return $e
}

function Get-FailReason($Err, $e) {
  # Только код и вид отказа: текст исключения может содержать адрес прокси.
  if (-not $e) { return $Err.Exception.GetType().Name }
  if ($e.Response) {
    $code = [int]$e.Response.StatusCode
    if ($code -eq 407) { return "HTTP 407: прокси требует входа, запустите с -ProxyCredential" }
    return "HTTP $code"
  }
  switch ([string]$e.Status) {
    "TrustFailure" { return "сертификат сервера не прошёл проверку (прокси подменяет сертификаты?)" }
    "NameResolutionFailure" { return "имя сервера не разрешается" }
    "ProxyNameResolutionFailure" { return "имя прокси не разрешается" }
    "ConnectFailure" { return "нет соединения" }
    "Timeout" { return "истекло время ожидания" }
  }
  # PowerShell 7 отдаёт отказ соединения как UnknownError с SocketException внутри.
  $inner = $e.InnerException
  while ($inner) {
    if ($inner -is [System.Net.Sockets.SocketException]) { return "нет соединения ($($inner.SocketErrorCode))" }
    $inner = $inner.InnerException
  }
  return [string]$e.Status
}

function Test-Permanent($e) {
  # 404 и прочие 4xx повтором не лечатся; 408 и 429 — лечатся.
  if (-not $e -or -not $e.Response) { return $false }
  $code = [int]$e.Response.StatusCode
  return ($code -ge 400 -and $code -lt 500 -and $code -ne 407 -and $code -ne 408 -and $code -ne 429)
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("stools-refs-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$packed = @()
$failed = @()
$skipped = @()
$code = 0
try {
  foreach ($it in $items) {
    if ($skipList -contains $it.Ref) { $skipped += $it.Name; continue }
    $url = $it.Url
    if ($BaseUrls.ContainsKey($it.Ref)) {
      $url = ([string]$BaseUrls[$it.Ref]).TrimEnd("/") + "/" + [System.Uri]::EscapeDataString($it.Name)
    }
    $path = Join-Path $tmp $it.Name
    $reason = ""
    for ($attempt = 0; $attempt -le $Retries; $attempt++) {
      if ($attempt -gt 0) { Start-Sleep -Seconds (2 * $attempt) }
      if ($attempt -eq 0) { Write-Host "→ $($it.Name)" } else { Write-Host "  повтор $attempt из $Retries" }
      try {
        Save-Feed $url $path
        $reason = ""
        break
      } catch {
        $webErr = Find-WebException $_
        $reason = Get-FailReason $_ $webErr
        $permanent = Test-Permanent $webErr
        # На .NET Framework незакрытый ответ с ошибкой занимает одно из двух соединений
        # к узлу, и следующий запрос к нему ждал бы до тайм-аута.
        if ($webErr -and $webErr.Response) { $webErr.Response.Close() }
        # Частично скачанный файл остаётся для докачки; при окончательном отказе удаляется ниже.
        if ($permanent -or $attempt -eq $Retries) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        if ($permanent) { break }
      }
    }
    if ($reason) {
      Write-Warning "$($it.Name): не скачан ($reason)"
      $failed += "$($it.Name) ($reason)"
    } else {
      $packed += $it.Name
    }
  }

  Write-Host ""
  if ($skipped.Count -gt 0) { Write-Host "пропущено по -Skip: $($skipped -join ', ')" }
  if ($failed.Count -gt 0) { Write-Host "не вошло: $($failed -join '; ')" -ForegroundColor Yellow }
  if ($packed.Count -eq 0) {
    Write-Host "ни один справочник не скачан, архив не создан" -ForegroundColor Red
    $code = 1
  } else {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Force }
    # ZipFile, а не Compress-Archive: тот держит всё в памяти, упирается в 2 ГБ и в 5.1
    # пишет обратные слэши в именах.
    $zip = [System.IO.Compression.ZipFile]::Open($Out, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($name in $packed) {
        # .gz уже сжат: второй раз жать — только время.
        $level = [System.IO.Compression.CompressionLevel]::Optimal
        if ($name.EndsWith(".gz")) { $level = [System.IO.Compression.CompressionLevel]::NoCompression }
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $tmp $name), $name, $level)
      }
    } finally {
      $zip.Dispose()
    }
    Write-Host "вошло: $($packed -join ', ')"
    Write-Host "архив: $Out ($([math]::Round((Get-Item -LiteralPath $Out).Length / 1MB, 1)) МБ)"
    Write-Host "загрузите его в STools: Настройки и данные → Справочники → Загрузить архив"
  }
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
exit $code
