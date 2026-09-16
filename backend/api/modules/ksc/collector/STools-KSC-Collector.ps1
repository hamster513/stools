<#
.SYNOPSIS
  STools — сборщик выгрузки Kaspersky Security Center (формат stools-ksc/1).

.DESCRIPTION
  Запускается на любой Windows-машине с доступом к серверу KSC по порту
  Open API (13299), от учётной записи KSC с правом чтения. Ничего не
  анализирует и не меняет: вызывает методы Open API и складывает ответы как
  есть в один JSON (gzip). Файл загружается в STools → Антивирус →
  Настройки и данные.

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
  Для автоматизации пароль можно передать переменной окружения
  STOOLS_KSC_PASSWORD; в командной строке пароль не передаётся.

.EXAMPLE
  .\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit -Internal
  .\STools-KSC-Collector.ps1 -Server 10.0.0.5 -User audit -Domain CORP -SkipTlsCheck -OutputPath C:\Temp\ksc.json.gz
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [int]$Port = 13299,
  [Parameter(Mandatory = $true)][string]$User,
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

if ($env:STOOLS_KSC_PASSWORD) { $plain = $env:STOOLS_KSC_PASSWORD }
else {
  if (-not $Password) { $Password = Read-Host -AsSecureString "Пароль $User" }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
  try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ($SkipTlsCheck) {
  # Windows PowerShell 5.1: глобальный обработчик; PowerShell 7: параметр -SkipCertificateCheck ниже.
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$base = "{0}://{1}:{2}/api/v1.0/" -f $Scheme, $Server, $Port
$script:session = $null

function Write-Step([string]$text) { Write-Host ("  " + $text) -ForegroundColor Cyan }

function B64([string]$s) { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# Set-StrictMode делает обращение к отсутствующему свойству ошибкой: читаем через Prop.
function Prop($o, $n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { return $o.$n }; return $null }
# KSC отдаёт числа и как 13, и как @{ type = "long"; value = 13 }.
function AsInt($v) { if ($null -eq $v) { return 0 }; if ($v -is [psobject] -and $v.PSObject.Properties["value"]) { $v = $v.value }; try { return [int]$v } catch { return 0 } }

function Invoke-Ksc([string]$method, $body = @{}) {
  $headers = @{ "Content-Type" = "application/json" }
  if ($script:session) { $headers["X-KSC-Session"] = $script:session }
  else {
    $internalFlag = if ($Internal) { "1" } else { "0" }
    $auth = 'KSCBasic user="{0}", pass="{1}", internal="{2}"' -f (B64 $User), (B64 $plain), $internalFlag
    if (-not $Internal -and $Domain) { $auth += ', domain="{0}"' -f (B64 $Domain) }
    $headers["Authorization"] = $auth
  }
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
$script:session = (Invoke-Ksc "Session.StartSession" "{}").PxgRetVal
try {
  Write-Step "Сервер"
  $static = Prop (Invoke-Ksc "HostGroup.GetStaticInfo" @{ pValues = @("KLADMSRV_SERVER_VERSION_ID","KLADMSRV_SERVER_HOSTNAME","KLADMSRV_PRODUCT_FULL_VERSION") }) "PxgRetVal"
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
      $hid = [string](Prop $h "KLHST_WKS_HOSTNAME")
      if (-not $hid) { continue }
      if (((AsInt (Prop $h "KLHST_WKS_STATUS")) -band 4) -eq 0) { continue }   # без агента продуктов нет
      try {
        $p = (Invoke-Ksc "HostGroup.GetHostProducts" @{ strHostName = $hid }).PxgRetVal
        $products[$hid] = $p
        $comp = @{}
        foreach ($prod in $p.PSObject.Properties) {
          if ($prod.Name -in @("1103","1093")) { continue }
          foreach ($ver in $prod.Value.PSObject.Properties) {
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
    $gid = AsInt (Prop $g "id")
    try { $effective[[string]$gid] = @((Prop (Invoke-Ksc "Policy.GetEffectivePoliciesForGroup" @{ nGroupId = $gid }) "PxgRetVal") | Where-Object { $null -ne $_ }) }
    catch { Write-Warning ("политики группы {0}: {1}" -f $gid, $_.Exception.Message) }
  }

  Write-Step "Задачи"
  $tasks = New-Object System.Collections.ArrayList
  $it = (Invoke-Ksc "Tasks.ResetTasksIterator" @{ nGroupId = -1; bGroupIdSignificant = $false; strProductName = ""; strVersion = ""; strComponentName = ""; strInstanceId = ""; strTaskName = ""; bIncludeSupergroups = $false }).strTaskIteratorId
  while ($true) {
    $t = Prop (Invoke-Ksc "Tasks.GetNextTask" @{ strTaskIteratorId = $it }) "pTaskData"
    if ($null -eq $t -or @($t.PSObject.Properties).Count -eq 0) { break }
    $tid = [string](Prop $t "TASK_UNIQUE_ID")
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

if (-not $OutputPath) { $OutputPath = "ksc-{0}-{1}.json.gz" -f $serverName, (Get-Date -Format "yyyyMMdd-HHmm") }
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
