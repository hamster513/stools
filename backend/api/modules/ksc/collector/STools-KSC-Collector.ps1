<#
.SYNOPSIS
  STools — сборщик выгрузки Kaspersky Security Center (формат stools-ksc/1).

.DESCRIPTION
  Запускается на любой Windows-машине с доступом к серверу KSC по порту
  Open API (13299), от учётной записи KSC с правом чтения. Ничего не
  анализирует и не меняет: вызывает методы Open API и складывает ответы как
  есть в один JSON (gzip). Файл загружается в STools → Антивирус →
  Настройки и данные.

.PARAMETER ConfigPath  Файл настроек (JSON): сервер, учётка, пароль, секрет второго фактора и остальное.
                       Параметры командной строки главнее файла. Шаблон создаёт -InitConfig.
.PARAMETER InitConfig  Записать шаблон файла настроек по указанному пути и выйти.
.PARAMETER Server      Адрес сервера KSC.
.PARAMETER Port        Порт Open API, по умолчанию 13299.
.PARAMETER User        Учётная запись KSC.
.PARAMETER Password    Пароль (SecureString); если не задан — будет запрошен.
.PARAMETER Internal    Внутренняя учётная запись KSC (иначе — доменная, см. -Domain).
.PARAMETER Domain      Домен доменной учётной записи.
.PARAMETER OutputPath  Куда писать файл; по умолчанию ksc-<сервер>-<дата>.json.gz.
.PARAMETER SkipTlsCheck Не проверять сертификат сервера (самоподписанный).
.PARAMETER SkipProducts Не запрашивать продукты и компоненты по каждому хосту (быстрее).
.PARAMETER PageSize    Размер страницы при чтении хостов, по умолчанию 500.
.PARAMETER Scheme      https (по умолчанию) или http — только для тестов.

.NOTES
  Пароль и секрет второго фактора в командной строке не передаются: они
  берутся из переменных окружения STOOLS_KSC_PASSWORD и STOOLS_KSC_TOTP_SECRET,
  затем из файла настроек (password, totp_secret); пароль, которого нет нигде,
  запрашивается. Если сервер требует второй фактор, а секрета нет, скрипт
  спросит шестизначный код из приложения-аутентификатора.
  Файл настроек содержит секреты: держите его доступным только себе и удалите
  после сбора.

.EXAMPLE
  .\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit -Internal
  .\STools-KSC-Collector.ps1 -Server 10.0.0.5 -User audit -Domain CORP -SkipTlsCheck -OutputPath C:\Temp\ksc.json.gz
  .\STools-KSC-Collector.ps1 -InitConfig .\ksc-config.json    # шаблон; заполнить и запустить:
  .\STools-KSC-Collector.ps1 -ConfigPath .\ksc-config.json
#>
[CmdletBinding()]
param(
  [string]$ConfigPath,
  [string]$InitConfig,
  [string]$Server,
  [int]$Port = 13299,
  [string]$User,
  [SecureString]$Password,
  [switch]$Internal,
  [string]$Domain = "",
  [string]$OutputPath,
  [switch]$SkipTlsCheck,
  [switch]$SkipProducts,
  [int]$PageSize = 500,
  [ValidateSet("https", "http")][string]$Scheme = "https"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$FormatVersion = "stools-ksc/1"
$CollectorVersion = "1.0"

if ($InitConfig) {
  if (-not [System.IO.Path]::IsPathRooted($InitConfig)) { $InitConfig = Join-Path $PWD.ProviderPath $InitConfig }
  $template = [ordered]@{
    server = ""; port = 13299; user = ""; password = ""; internal = $false; domain = ""; totp_secret = ""
    skip_tls_check = $false; skip_products = $false; page_size = 500; output_path = ""
  }
  [System.IO.File]::WriteAllText($InitConfig, ($template | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "Шаблон записан: $InitConfig" -ForegroundColor Green
  Write-Host "В файле будут пароль и секрет второго фактора: закройте к нему доступ и удалите после сбора."
  Write-Host "Пути в JSON пишутся с удвоенной обратной чертой (C:\\Temp) или с прямой (C:/Temp); output_path можно оставить пустым."
  exit 0
}

# Файл настроек: всё, что не задано в командной строке, берётся из него.
$cfg = $null
if ($ConfigPath) {
  if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Файл настроек не найден: $ConfigPath" }
  try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
  catch { throw ("Файл настроек не разобран как JSON: {0}. В путях Windows обратную косую черту нужно удваивать (C:\\Temp\\ksc.json.gz) или писать прямую (C:/Temp/ksc.json.gz)." -f $ConfigPath) }
}
function Cfg([string]$name) { if ($null -ne $cfg -and $cfg.PSObject.Properties[$name]) { return $cfg.$name }; return $null }
$bound = $PSBoundParameters
if (-not $bound.ContainsKey("Server") -and (Cfg "server")) { $Server = [string](Cfg "server") }
if (-not $bound.ContainsKey("Port") -and (Cfg "port")) { $Port = [int](Cfg "port") }
if (-not $bound.ContainsKey("User") -and (Cfg "user")) { $User = [string](Cfg "user") }
if (-not $bound.ContainsKey("Internal") -and (Cfg "internal")) { $Internal = [bool](Cfg "internal") }
if (-not $bound.ContainsKey("Domain") -and (Cfg "domain")) { $Domain = [string](Cfg "domain") }
if (-not $bound.ContainsKey("OutputPath") -and (Cfg "output_path")) { $OutputPath = [string](Cfg "output_path") }
if (-not $bound.ContainsKey("SkipTlsCheck") -and (Cfg "skip_tls_check")) { $SkipTlsCheck = [bool](Cfg "skip_tls_check") }
if (-not $bound.ContainsKey("SkipProducts") -and (Cfg "skip_products")) { $SkipProducts = [bool](Cfg "skip_products") }
if (-not $bound.ContainsKey("PageSize") -and (Cfg "page_size")) { $PageSize = [int](Cfg "page_size") }
if (-not $bound.ContainsKey("Scheme") -and (Cfg "scheme")) { $Scheme = [string](Cfg "scheme") }
if (-not $Server) { $Server = Read-Host "Сервер KSC" }
if (-not $User) { $User = Read-Host "Учётная запись" }

$totpSecret = ""
if ($env:STOOLS_KSC_TOTP_SECRET) { $totpSecret = $env:STOOLS_KSC_TOTP_SECRET }
elseif (Cfg "totp_secret") { $totpSecret = [string](Cfg "totp_secret") }

if ($env:STOOLS_KSC_PASSWORD) { $plain = $env:STOOLS_KSC_PASSWORD }
elseif (Cfg "password") { $plain = [string](Cfg "password") }
else {
  if (-not $Password) { $Password = Read-Host -AsSecureString "Пароль $User" }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
  try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ($SkipTlsCheck) {
  # Windows PowerShell 5.1: глобальный обработчик; PowerShell 7: параметр -SkipCertificateCheck ниже.
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Делегат из скриптблока вызывается в потоке без runspace и роняет соединение,
    # поэтому обработчик компилируется.
    if (-not ("STools.TrustAll" -as [type])) {
      Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace STools {
  public static class TrustAll {
    public static bool Validate(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }
    public static void Enable() { ServicePointManager.ServerCertificateValidationCallback = Validate; }
  }
}
"@
    }
    [STools.TrustAll]::Enable()
  }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$base = "{0}://{1}:{2}/api/v1.0/" -f $Scheme, $Server, $Port
$script:session = $null

function Write-Step([string]$text) { Write-Host ("  " + $text) -ForegroundColor Cyan }

function B64([string]$s) { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# Set-StrictMode делает обращение к отсутствующему свойству ошибкой: читаем через Prop.
function Prop($o, $n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { return $o.$n }; return $null }
# Живой KSC заворачивает каждую запись и вложенный контейнер в @{ type = "params"; value = ... }:
# читаем сквозь обёртку, в файл кладём как пришло.
function Unwrap($o) { if ($null -ne $o -and $o -is [psobject] -and $o.PSObject.Properties["type"] -and $o.PSObject.Properties["value"] -and $o.type -eq "params") { return $o.value }; return $o }
# KSC отдаёт числа и как 13, и как @{ type = "long"; value = 13 }.
function AsInt($v) { if ($null -eq $v) { return 0 }; if ($v -is [psobject] -and $v.PSObject.Properties["value"]) { $v = $v.value }; try { return [int]$v } catch { return 0 } }

# RFC 6238: SHA1, шаг 30 с, 6 цифр; секрет в base32, как его показывает KSC при подключении аутентификатора.
function Get-TotpCode([string]$secret) {
  $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  $bits = New-Object System.Text.StringBuilder
  foreach ($ch in ($secret.ToUpper() -replace "[\s=-]", "").ToCharArray()) {
    $i = $alphabet.IndexOf($ch)
    if ($i -lt 0) { throw "Секрет второго фактора не в base32" }
    [void]$bits.Append([Convert]::ToString($i, 2).PadLeft(5, "0"))
  }
  $s = $bits.ToString()
  $n = [int][Math]::Floor($s.Length / 8)
  $key = New-Object byte[] $n
  for ($i = 0; $i -lt $n; $i++) { $key[$i] = [Convert]::ToByte($s.Substring($i * 8, 8), 2) }
  $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
  $counter = [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalSeconds / 30)
  $msg = [BitConverter]::GetBytes($counter)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($msg) }
  $hmac = New-Object System.Security.Cryptography.HMACSHA1 -ArgumentList @(, $key)
  $hash = $hmac.ComputeHash($msg)
  $o = $hash[$hash.Length - 1] -band 0x0F
  $bin = (([int]$hash[$o] -band 0x7F) -shl 24) -bor ([int]$hash[$o + 1] -shl 16) -bor ([int]$hash[$o + 2] -shl 8) -bor [int]$hash[$o + 3]
  return ($bin % 1000000).ToString("000000")
}

# Один запрос входа. Отказ (401/403) — не исключение, а ответ: по нему видно, просит ли сервер второй фактор.
function Send-Login([hashtable]$headers) {
  $p = @{ Uri = ($base + "Session.StartSession"); Method = "Post"; Headers = $headers; Body = ([Text.Encoding]::UTF8.GetBytes("{}")); ContentType = "application/json"; UseBasicParsing = $true }
  $h = @{}
  if ($PSVersionTable.PSVersion.Major -ge 7) {
    $p["SkipHttpErrorCheck"] = $true
    if ($SkipTlsCheck) { $p["SkipCertificateCheck"] = $true }
    $r = Invoke-WebRequest @p
    foreach ($k in $r.Headers.Keys) { $h[$k.ToLower()] = [string](@($r.Headers[$k])[0]) }
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Headers = $h; Text = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray()) }
  }
  try {
    $r = Invoke-WebRequest @p
    foreach ($k in $r.Headers.Keys) { $h[$k.ToLower()] = [string]$r.Headers[$k] }
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Headers = $h; Text = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray()) }
  } catch [System.Net.WebException] {
    $resp = $_.Exception.Response
    if ($null -eq $resp) { throw }
    foreach ($k in $resp.Headers.AllKeys) { $h[$k.ToLower()] = [string]$resp.Headers[$k] }
    return [pscustomobject]@{ Status = [int]$resp.StatusCode; Headers = $h; Text = "" }
  }
}

# Вход: пароль, а если сервер отвечает 401 с KSCMFA — второй запрос с кодом TOTP и выданной промежуточной сессией.
function Start-KscSession {
  $internalFlag = if ($Internal) { "1" } else { "0" }
  $auth = 'KSCBasic user="{0}", pass="{1}", internal="{2}"' -f (B64 $User), (B64 $plain), $internalFlag
  if (-not $Internal -and $Domain) { $auth += ', domain="{0}"' -f (B64 $Domain) }
  $r = Send-Login @{ "Authorization" = $auth }
  if ($r.Status -eq 401 -and ([string]$r.Headers["www-authenticate"]) -match "KSCMFA") {
    Write-Step "Сервер просит второй фактор"
    $code = if ($totpSecret) { Get-TotpCode $totpSecret } else { Read-Host "Код из приложения-аутентификатора (6 цифр)" }
    $r = Send-Login @{ "Authorization" = ('KSCMFA totp="{0}"' -f $code); "X-KSC-Session" = [string]$r.Headers["x-ksc-session"] }
  }
  if ($r.Status -eq 401 -or $r.Status -eq 403) { throw ("Вход отклонён (HTTP {0}): проверьте логин, пароль, тип учётной записи (-Internal или -Domain) и второй фактор" -f $r.Status) }
  if ($r.Status -ne 200) { throw ("KSC ответил HTTP {0} на вход" -f $r.Status) }
  $obj = $r.Text | ConvertFrom-Json
  if ($obj.PSObject.Properties["PxgError"]) { throw ("KSC вход: {0}" -f $obj.PxgError.message) }
  return [string](Prop $obj "PxgRetVal")
}

function Invoke-Ksc([string]$method, $body = @{}) {
  $headers = @{ "Content-Type" = "application/json"; "X-KSC-Session" = $script:session }
  $json = if ($body -is [string]) { $body } else { $body | ConvertTo-Json -Depth 10 -Compress }
  if ($json -eq "null") { $json = "{}" }
  $params = @{ Uri = ($base + $method); Method = "Post"; Headers = $headers; Body = ([Text.Encoding]::UTF8.GetBytes($json)); ContentType = "application/json" }
  if ($SkipTlsCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $params["SkipCertificateCheck"] = $true }
  $raw = Invoke-WebRequest @params -UseBasicParsing
  $text = [Text.Encoding]::UTF8.GetString($raw.RawContentStream.ToArray())
  if (-not $text) { return @{} }
  $obj = $text | ConvertFrom-Json
  if ($obj.PSObject.Properties["PxgError"]) { throw ("KSC {0}: {1}" -f $method, $obj.PxgError.message) }
  return $obj
}

function Read-Accessor([string]$accessor) {
  $total = (Invoke-Ksc "ChunkAccessor.GetItemsCount" @{ strAccessor = $accessor }).PxgRetVal
  $items = New-Object System.Collections.ArrayList
  $start = 0
  while ($start -lt $total) {
    $chunk = Invoke-Ksc "ChunkAccessor.GetItemsChunk" @{ strAccessor = $accessor; nStart = $start; nCount = $PageSize }
    $arr = @((Prop (Prop $chunk "pChunk") "KLCSP_ITERATOR_ARRAY") | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) { break }
    foreach ($i in $arr) { [void]$items.Add($i) }
    $start += $arr.Count
    Write-Step ("  {0} из {1}" -f $start, $total)
  }
  Invoke-Ksc "ChunkAccessor.Release" @{ strAccessor = $accessor } | Out-Null
  return ,$items.ToArray()
}

$HostFields = @(
  "KLHST_WKS_HOSTNAME","KLHST_WKS_DN","KLHST_WKS_WINHOSTNAME","KLHST_WKS_WINDOMAIN","KLHST_WKS_DNSDOMAIN","KLHST_WKS_DNSNAME","KLHST_WKS_FQDN",
  "KLHST_WKS_GROUPID","KLHST_WKS_OS_NAME","KLHST_WKS_OS_VER_MAJOR","KLHST_WKS_OS_VER_MINOR","KLHST_WKS_IP_LONG","KLHST_WKS_CTYPE",
  "KLHST_WKS_STATUS","KLHST_WKS_STATUS_ID","KLHST_WKS_STATUS_MASK","KLHST_WKS_STATUS_HSDP","KLHST_WKS_RTP_STATE","KLHST_WKS_RTP_ERROR_CODE",
  "KLHST_WKS_RTP_AV_VERSION","KLHST_WKS_RTP_AV_BASES_TIME","KLHST_WKS_LAST_FULLSCAN","KLHST_WKS_LAST_VISIBLE","KLHST_WKS_LAST_NAGENT_CONNECTED",
  "KLHST_WKS_LAST_UPDATE","KLHST_WKS_LAST_INFOUDATE","KLHST_WKS_NAG_VERSION","KLHST_WKS_VIRUS_COUNT","KLHST_WKS_UNCURED_COUNT",
  "KLHST_WKS_FROM_UNASSIGNED","KLHST_WKS_RBT_REQUIRED","KLHST_WKS_LAST_SYSTEM_START","KLHST_WKS_CREATED"
)
$GroupFields = @("id","name","parentId","grp_full_name","level","hostsNum","childGroupsNum","creationDate","lastUpdate")
$LicenseFields = @("KLLIC_SERIAL","KLLIC_PROD_NAME","KLLIC_KEY_TYPE","KLLIC_CREATION_DATE","KLLIC_LIMIT_DATE","KLLIC_LICENSE_PERIOD","KLLIC_LIC_COUNT",
  "KLLIC_NHOSTS_ASCURRENT","KLLIC_NHOSTS_ASNEXT","KLLIC_USED_BY_ADM_SRV","KLLICSRV_KEY_INSTALLED","KLLIC_APP_ID","KLLIC_MAJ_VER")

Write-Host "STools KSC Collector $CollectorVersion → $base" -ForegroundColor Green
Write-Step "Вход"
$script:session = Start-KscSession
if (-not $script:session) { throw "KSC не выдал сессию" }
try {
  Write-Step "Сервер"
  $static = Unwrap (Prop (Invoke-Ksc "HostGroup.GetStaticInfo" @{ pValues = @("KLADMSRV_SERVER_VERSION_ID","KLADMSRV_SERVER_HOSTNAME","KLADMSRV_PRODUCT_FULL_VERSION") }) "PxgRetVal")
  $domains = @((Prop (Invoke-Ksc "HostGroup.GetDomains" "{}") "PxgRetVal") | Where-Object { $null -ne $_ })

  Write-Step "Группы"
  $ga = (Invoke-Ksc "HostGroup.FindGroups" @{ wstrFilter = ""; vecFieldsToReturn = $GroupFields; vecFieldsToOrder = @(); lMaxLifeTime = 600 }).strAccessor
  $groups = Read-Accessor $ga

  Write-Step "Хосты"
  $ha = (Invoke-Ksc "HostGroup.FindHosts" @{ wstrFilter = ""; vecFieldsToReturn = $HostFields; vecFieldsToOrder = @(); pParams = @{ KLGRP_FIND_FROM_CUR_VS_ONLY = $true }; lMaxLifeTime = 600 }).strAccessor
  $hosts = Read-Accessor $ha

  $products = @{}
  $components = @{}
  if (-not $SkipProducts) {
    Write-Step ("Продукты и компоненты ({0} хостов)" -f $hosts.Count)
    $n = 0
    foreach ($h in $hosts) {
      $n++
      $hv = Unwrap $h
      $hid = [string](Prop $hv "KLHST_WKS_HOSTNAME")
      if (-not $hid) { continue }
      if (((AsInt (Prop $hv "KLHST_WKS_STATUS")) -band 4) -eq 0) { continue }   # без агента продуктов нет
      try {
        $p = (Invoke-Ksc "HostGroup.GetHostProducts" @{ strHostName = $hid }).PxgRetVal
        $products[$hid] = $p
        $comp = @{}
        foreach ($prod in (Unwrap $p).PSObject.Properties) {
          if ($prod.Name -in @("1103","1093")) { continue }
          foreach ($ver in (Unwrap $prod.Value).PSObject.Properties) {
            try {
              $c = (Invoke-Ksc "HostGroup.GetComponentsForProductOnHost" @{ strHostName = $hid; strProductName = $prod.Name; strProductVersion = $ver.Name }).PxgRetVal
              $comp["{0}/{1}" -f $prod.Name, $ver.Name] = @($c)
            } catch { Write-Warning ("компоненты {0} {1}: {2}" -f $hid, $prod.Name, $_.Exception.Message) }
          }
        }
        if ($comp.Count -gt 0) { $components[$hid] = $comp }
      } catch { Write-Warning ("продукты {0}: {1}" -f $hid, $_.Exception.Message) }
      if ($n % 100 -eq 0) { Write-Step ("  {0} из {1}" -f $n, $hosts.Count) }
    }
  }

  Write-Step "Политики"
  $policies = @((Prop (Invoke-Ksc "Policy.GetPoliciesForGroup" @{ nGroupId = -1 }) "PxgRetVal") | Where-Object { $null -ne $_ })
  $effective = @{}
  foreach ($g in $groups) {
    $gid = AsInt (Prop (Unwrap $g) "id")
    try { $effective[[string]$gid] = @((Prop (Invoke-Ksc "Policy.GetEffectivePoliciesForGroup" @{ nGroupId = $gid }) "PxgRetVal") | Where-Object { $null -ne $_ }) }
    catch { Write-Warning ("политики группы {0}: {1}" -f $gid, $_.Exception.Message) }
  }

  Write-Step "Задачи"
  $tasks = New-Object System.Collections.ArrayList
  $it = (Invoke-Ksc "Tasks.ResetTasksIterator" @{ nGroupId = -1; bGroupIdSignificant = $false; strProductName = ""; strVersion = ""; strComponentName = ""; strInstanceId = ""; strTaskName = ""; bIncludeSupergroups = $false }).strTaskIteratorId
  while ($true) {
    $t = Prop (Invoke-Ksc "Tasks.GetNextTask" @{ strTaskIteratorId = $it }) "pTaskData"
    if ($null -eq $t -or @($t.PSObject.Properties).Count -eq 0) { break }
    $tid = [string](Prop (Unwrap $t) "TASK_UNIQUE_ID")
    if ($tid) { try { $t | Add-Member -NotePropertyName "statistics" -NotePropertyValue (Invoke-Ksc "Tasks.GetTaskStatistics" @{ strTask = $tid }).PxgRetVal -Force } catch {} }
    [void]$tasks.Add($t)
  }
  Invoke-Ksc "Tasks.ReleaseTasksIterator" @{ strTaskIteratorId = $it } | Out-Null

  Write-Step "Лицензии"
  $licenses = New-Object System.Collections.ArrayList
  $lk = Invoke-Ksc "LicenseKeys.EnumKeys" @{ pFields = $LicenseFields; pFieldsToOrder = @(); pOptions = @{}; lTimeoutSec = 600 }
  $li = [string](Prop $lk "wstrIterator")
  if ($li) {   # ключей нет — итератора тоже нет
    while ($true) {
      $chunk = Invoke-Ksc "GroupSyncIterator.GetNextItems" @{ szwIterator = $li; nCount = 50 }
      foreach ($k in @((Prop (Prop $chunk "pData") "KLCSP_ITERATOR_ARRAY") | Where-Object { $null -ne $_ })) { [void]$licenses.Add($k) }
      $eof = Prop $chunk "bEOF"
      if ($null -eq $eof -or $eof) { break }
    }
    Invoke-Ksc "GroupSyncIterator.ReleaseIterator" @{ szwIterator = $li } | Out-Null
  }
} finally {
  try { Invoke-Ksc "Session.EndSession" "{}" | Out-Null } catch {}
}

$serverName = [string](Prop $static "KLADMSRV_SERVER_HOSTNAME")
if (-not $serverName) { $serverName = $Server }
$export = [ordered]@{
  format = $FormatVersion
  server = @{ name = $serverName; version = [string](Prop $static "KLADMSRV_PRODUCT_FULL_VERSION"); collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); collector = "powershell"; collector_version = $CollectorVersion; user = $User; host = $Server }
  groups = $groups; hosts = $hosts; host_products = $products; host_components = $components
  policies = $policies; effective_policies = $effective; tasks = $tasks.ToArray(); licenses = $licenses.ToArray()
  static = $static; domains = $domains
}

$defaultName = "ksc-{0}-{1}.json.gz" -f $serverName, (Get-Date -Format "yyyyMMdd-HHmm")
if (-not $OutputPath) { $OutputPath = $defaultName }
# Указан каталог, а не файл — кладём в него файл с именем по умолчанию.
elseif ($OutputPath -match '[\\/]$' -or (Test-Path -LiteralPath $OutputPath -PathType Container)) { $OutputPath = Join-Path $OutputPath $defaultName }
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $PWD.ProviderPath $OutputPath }
Write-Step "Запись $OutputPath"
$json = $export | ConvertTo-Json -Depth 12 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$out = [System.IO.File]::Create($OutputPath)
try {
  $gz = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
  $gz.Write($bytes, 0, $bytes.Length)
  $gz.Dispose()
} finally { $out.Dispose() }
Write-Host ("Готово: хостов {0}, групп {1}, политик {2}, задач {3}, размер {4:N0} байт" -f $hosts.Count, $groups.Count, $policies.Count, $tasks.Count, (Get-Item $OutputPath).Length) -ForegroundColor Green
Write-Host "Загрузите файл в STools: Антивирус → Настройки и данные → Загрузить выгрузку."
