<#
.SYNOPSIS
  STools — сборщик выгрузки Kaspersky Security Center (формат stools-ksc/1).

.DESCRIPTION
  Запускается на любой Windows-машине с доступом к серверу KSC по порту
  Open API (13299), от учётной записи KSC с правом чтения. Ничего не
  анализирует и не меняет: вызывает методы Open API и складывает ответы как
  есть в один JSON (gzip). Файл загружается в STools → Антивирус →
  Настройки и данные.

  Что собирается: группы, хосты (включая сборку ОС, архитектуру, тип
  виртуализации, признак ожидающей перезагрузки), продукты и компоненты,
  политики, задачи со статистикой, лицензии, а также роли и внутренние
  учётные записи KSC, состояние обязательной двухэтапной проверки,
  сертификат сервера, подчинённые серверы и точки распространения. Из
  учётных записей — только отображаемое имя, логин, UPN и признаки
  внутренней/встроенной учётки; весь каталог AD не выгружается. Учётке без
  прав на отдельную секцию сбор не мешает: секция остаётся пустой, а
  причина попадает в предупреждения (Write-Warning и server.warnings).

.PARAMETER ConfigPath  Файл настроек (JSON): сервер, учётка, пароль, секрет второго фактора и остальное.
                       Параметры командной строки главнее файла. Шаблон создаёт -InitConfig.
.PARAMETER InitConfig  Записать шаблон файла настроек по указанному пути и выйти. Доступ к файлу — только
                       у текущей учётной записи (Windows: icacls, иначе chmod 600).
.PARAMETER DeleteConfigAfterRun Удалить файл настроек после успешного сбора (то же — ключ delete_after_run в файле).
.PARAMETER Server      Адрес сервера KSC.
.PARAMETER Port        Порт Open API, по умолчанию 13299.
.PARAMETER User        Учётная запись KSC.
.PARAMETER Password    Пароль (SecureString); если не задан — будет запрошен.
.PARAMETER Internal    Внутренняя учётная запись KSC (иначе — доменная, см. -Domain).
.PARAMETER Domain      Домен доменной учётной записи.
.PARAMETER OutputPath  Куда писать файл; по умолчанию ksc-<сервер>-<дата>.json.gz (в имени сервера всё,
                       кроме латиницы, цифр, точки, дефиса и подчёркивания, заменяется на _).
.PARAMETER SkipTlsCheck Не проверять сертификат сервера KSC (самоподписанный); остальные адреса проверяются как обычно.
.PARAMETER SkipProducts Не запрашивать продукты и компоненты по каждому хосту (быстрее).
.PARAMETER SkipPolicyContents Не собирать содержимое политик (секция policy_contents; файл заметно больше).
.PARAMETER PageSize    Размер страницы при чтении хостов, по умолчанию 500.
.PARAMETER Scheme      https (по умолчанию) или http — только для тестов.

.NOTES
  Пароль и секрет второго фактора в командной строке не передаются: они
  берутся из переменных окружения STOOLS_KSC_PASSWORD и STOOLS_KSC_TOTP_SECRET,
  затем из файла настроек (password, totp_secret); пароль, которого нет нигде,
  запрашивается. Если сервер требует второй фактор, а секрета нет, скрипт
  спросит шестизначный код из приложения-аутентификатора.
  Файл настроек содержит секреты: -InitConfig закрывает к нему доступ всем,
  кроме вас; удалите его после сбора или запускайте с -DeleteConfigAfterRun.

.EXAMPLE
  .\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit -Internal
  .\STools-KSC-Collector.ps1 -Server 10.0.0.5 -User audit -Domain CORP -SkipTlsCheck -OutputPath C:\Temp\ksc.json.gz
  .\STools-KSC-Collector.ps1 -InitConfig .\ksc-config.json    # шаблон; заполнить и запустить:
  .\STools-KSC-Collector.ps1 -ConfigPath .\ksc-config.json -DeleteConfigAfterRun
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
  [switch]$SkipPolicyContents,
  [switch]$DeleteConfigAfterRun,
  [int]$PageSize = 500,
  [ValidateSet("https", "http")][string]$Scheme = "https"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$FormatVersion = "stools-ksc/1"
$CollectorVersion = "1.1"
#: Имя секции или ключ на любой глубине её параметров с одним из этих слов (подстрокой, без учёта
#: регистра) — всё поддерево под ним в режиме скрытия: строки → "<скрыто>", ключи остаются; двоичные
#: значения скрываются всегда (см. Hide-Value). Список совпадает с SECRET_MARKERS в
#: api/modules/ksc/core/secrets.py (сверяет тест). Не больше стольки политик и байт на секцию.
$SecretMarkers = @("PASSWORD", "PASSWD", "PWD", "SECRET", "CRYPTED", "TOKEN", "CREDENTIAL", "PRIVATE", "PASSPHRASE", "APIKEY", "API_KEY", "AUTH", "PIN", "KEY")
$PolicyContentsMaxPolicies = 200
$PolicyContentsSectionMaxBytes = 2097152

if ($InitConfig) {
  if (-not [System.IO.Path]::IsPathRooted($InitConfig)) { $InitConfig = Join-Path $PWD.ProviderPath $InitConfig }
  $template = [ordered]@{
    server = ""; port = 13299; user = ""; password = ""; internal = $false; domain = ""; totp_secret = ""
    skip_tls_check = $false; skip_products = $false; skip_policy_contents = $false; page_size = 500; output_path = ""
    delete_after_run = $false
  }
  [System.IO.File]::WriteAllText($InitConfig, ($template | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
  # В файл лягут пароль и секрет второго фактора: читать и менять его может только текущая учётная запись.
  if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    # (M) — чтение, запись и удаление: без удаления -DeleteConfigAfterRun не уберёт файл после /inheritance:r.
    & icacls $InitConfig /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(M)" | Out-Null
  } else {
    & chmod 600 -- $InitConfig
  }
  if ($LASTEXITCODE -ne 0) { throw "Не удалось закрыть доступ к файлу настроек: $InitConfig" }
  Write-Host "Шаблон записан: $InitConfig" -ForegroundColor Green
  Write-Host "Доступ к файлу — только у вас. В нём будут пароль и секрет второго фактора: удалите его после сбора или задайте delete_after_run = true (или -DeleteConfigAfterRun)."
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
if (-not $bound.ContainsKey("SkipPolicyContents") -and (Cfg "skip_policy_contents")) { $SkipPolicyContents = [bool](Cfg "skip_policy_contents") }
if (-not $bound.ContainsKey("PageSize") -and (Cfg "page_size")) { $PageSize = [int](Cfg "page_size") }
if (-not $bound.ContainsKey("Scheme") -and (Cfg "scheme")) { $Scheme = [string](Cfg "scheme") }
if (-not $bound.ContainsKey("DeleteConfigAfterRun") -and (Cfg "delete_after_run")) { $DeleteConfigAfterRun = [bool](Cfg "delete_after_run") }
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

# -SkipTlsCheck. PowerShell 7: параметр -SkipCertificateCheck у каждого запроса (Send-Login, Invoke-Ksc).
# Windows PowerShell 5.1 такого параметра не знает, и проверку заменяет обработчик ServicePointManager —
# общий на весь процесс PowerShell. Поэтому он пропускает без проверки только адрес KSC (-Server),
# остальные адреса отдаёт прежнему обработчику или стандартной проверке, а в конце скрипта (finally)
# прежний обработчик возвращается на место. Делегат из скриптблока вызывается в потоке без runspace
# и роняет соединение, поэтому обработчик компилируется.
$tlsHook = $SkipTlsCheck -and $PSVersionTable.PSVersion.Major -lt 6
if ($tlsHook -and -not ("STools.KscTls" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace STools {
  public static class KscTls {
    static string host;
    static RemoteCertificateValidationCallback previous;
    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
      HttpWebRequest request = sender as HttpWebRequest;
      string target = request != null ? request.RequestUri.Host : sender as string;
      if (host != null && target != null && string.Equals(target, host, StringComparison.OrdinalIgnoreCase)) { return true; }
      if (previous != null) { return previous(sender, certificate, chain, errors); }
      return errors == SslPolicyErrors.None;
    }
    public static void Enable(string kscHost) {
      previous = ServicePointManager.ServerCertificateValidationCallback;
      host = kscHost;
      ServicePointManager.ServerCertificateValidationCallback = Validate;
    }
    public static void Restore() {
      ServicePointManager.ServerCertificateValidationCallback = previous;
      previous = null;
      host = null;
    }
  }
}
"@
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$base = "{0}://{1}:{2}/api/v1.0/" -f $Scheme, $Server, $Port
$script:session = $null

# Ход работы: у каждой строки — время от начала сбора. Строка без отступа открывает шаг (его имя
# попадёт в сообщение об ошибке), с отступом — уточняет текущий: счётчик или итог шага.
$script:started = Get-Date
$script:stage = ""
function Write-Step([string]$text) {
  if (-not $text.StartsWith(" ")) { $script:stage = $text }
  $t = (Get-Date) - $script:started
  Write-Host ("  [{0:00}:{1:00}] {2}" -f [int][math]::Floor($t.TotalMinutes), $t.Seconds, $text) -ForegroundColor Cyan
}

function B64([string]$s) { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# Set-StrictMode делает обращение к отсутствующему свойству ошибкой: читаем через Prop.
function Prop($o, $n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { return $o.$n }; return $null }
# Живой KSC заворачивает каждую запись и вложенный контейнер в @{ type = "params"; value = ... }:
# читаем сквозь обёртку, в файл кладём как пришло.
function Unwrap($o) { if ($null -ne $o -and $o -is [psobject] -and $o.PSObject.Properties["type"] -and $o.PSObject.Properties["value"] -and $o.type -eq "params") { return $o.value }; return $o }
# KSC отдаёт числа и как 13, и как @{ type = "long"; value = 13 }.
function AsInt($v) { if ($null -eq $v) { return 0 }; if ($v -is [psobject] -and $v.PSObject.Properties["value"]) { $v = $v.value }; try { return [int]$v } catch { return 0 } }
# KSC отдаёт булевы и как $true/$false, и как @{ type = "boolean"; value = $false } — типизированный
# ноль не должен читаться как безусловная правда.
function AsBool($v) { if ($null -eq $v) { return $false }; if ($v -is [psobject] -and $v.PSObject.Properties["value"]) { $v = $v.value }; try { return [bool]$v } catch { return $false } }
# SecretMarkers подстрокой в имени, без учёта регистра: PASSWORD_HASH, KLPRSS_Password, AdminPassword — да.
function Test-SecretMarker([string]$name) {
  $upper = $name.ToUpper()
  foreach ($m in $SecretMarkers) { if ($upper.Contains($m)) { return $true } }
  return $false
}
# Типизированное значение KSC: @{ type = <вид>; value = ... } — ровно два свойства, type — строка.
function Test-TypedWrapper($v) {
  if ($null -eq $v -or $v -isnot [System.Management.Automation.PSCustomObject]) { return $false }
  # Не `.Properties.Name`: в строгом режиме перечисление свойства у пустого набора — ошибка, а пустой
  # объект `{}` в параметрах задач и политик встречается (задача без расписания).
  $names = @($v.PSObject.Properties | ForEach-Object { $_.Name })
  return ($names.Count -eq 2) -and ($names -contains "type") -and ($names -contains "value") -and ($v.type -is [string])
}
# Обход поддерева с режимом скрытия. Ключ с признаком секрета включает режим для всего, что под ним.
# В режиме строки → "<скрыто>"; булевы, числа и прочие типизированные значения остаются. Двоичные
# значения (@{ type = "binary"; ... }) скрываются всегда, под любым ключом. Обёртки params проходятся
# насквозь и остаются на месте, списки — поэлементно. То же правило — hide_secrets в
# api/modules/ksc/core/secrets.py.
# Списки возвращаются через ",": иначе конвейер разворачивает список из одного элемента в скаляр,
# а пустой — в $null. По той же причине результат присваивается переменной, а не выражением if.
function Hide-Value($v, [bool]$hide) {
  if ($null -eq $v) { return $null }
  if (Test-TypedWrapper $v) {
    if ($v.type -eq "params") {
      $inner = Hide-Value $v.value $hide
      return [ordered]@{ type = "params"; value = $inner }
    }
    if ($v.type -eq "binary") { return "<скрыто>" }
    return $v
  }
  if ($v -is [System.Management.Automation.PSCustomObject]) {
    $out = [ordered]@{}
    foreach ($p in $v.PSObject.Properties) {
      $childHide = $hide -or (Test-SecretMarker $p.Name)
      $child = Hide-Value $p.Value $childHide
      $out[$p.Name] = $child
    }
    return $out
  }
  if ($v -is [array]) {
    $items = New-Object System.Collections.ArrayList
    foreach ($item in $v) {
      $child = Hide-Value $item $hide
      [void]$items.Add($child)
    }
    return ,($items.ToArray())
  }
  if ($hide -and (($v -is [string]) -or ($v -is [datetime]))) { return "<скрыто>" }
  return $v
}
# Секреты в содержимом политики: имя секции или ключ на любой глубине с признаком секрета —
# всё поддерево под ним в режиме скрытия (Hide-Value). Секция хранится как пришла: меняются только
# скрытые значения, обёртки остаются.
function Hide-Secrets([string]$sectionName, $params) {
  $hidden = Hide-Value $params (Test-SecretMarker $sectionName)
  return ,$hidden
}
# HTTP-код отказа из исключения Invoke-WebRequest (PowerShell 5.1 — WebException, 7 — HttpResponseException);
# 0, если ошибка не про ответ сервера (PxgError, обрыв связи).
function HttpStatus($err) {
  $ex = $err.Exception
  if ($null -eq $ex -or -not $ex.PSObject.Properties["Response"]) { return 0 }
  $resp = $ex.Response
  if ($null -eq $resp -or -not $resp.PSObject.Properties["StatusCode"]) { return 0 }
  try { return [int]$resp.StatusCode } catch { return 0 }
}

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

# SrvView: тот же итератор, что ChunkAccessor, но с ResetIterator/GetRecordRange (nEnd включительно) и своим ReleaseIterator.
function Read-SrvView([string]$view, [string[]]$fields, [string]$filter = "") {
  $it = (Invoke-Ksc "SrvView.ResetIterator" @{ wstrViewName = $view; wstrFilter = $filter; vecFieldsToReturn = $fields; vecFieldsToOrder = @(); pParams = @{}; lifetimeSec = 600 }).wstrIteratorId
  try {
    $total = (Invoke-Ksc "SrvView.GetRecordCount" @{ wstrIteratorId = $it }).PxgRetVal
    $items = New-Object System.Collections.ArrayList
    $start = 0
    while ($start -lt $total) {
      $end = [Math]::Min($start + 500, $total) - 1
      $chunk = Invoke-Ksc "SrvView.GetRecordRange" @{ wstrIteratorId = $it; nStart = $start; nEnd = $end }
      $arr = @((Prop (Prop $chunk "pRecords") "KLCSP_ITERATOR_ARRAY") | Where-Object { $null -ne $_ })
      if ($arr.Count -eq 0) { break }
      foreach ($i in $arr) { [void]$items.Add($i) }
      $start += $arr.Count
    }
    return ,$items.ToArray()
  } finally {
    Invoke-Ksc "SrvView.ReleaseIterator" @{ wstrIteratorId = $it } | Out-Null
  }
}

$HostFields = @(
  "KLHST_WKS_HOSTNAME","KLHST_WKS_DN","KLHST_WKS_WINHOSTNAME","KLHST_WKS_WINDOMAIN","KLHST_WKS_DNSDOMAIN","KLHST_WKS_DNSNAME","KLHST_WKS_FQDN",
  "KLHST_WKS_GROUPID","KLHST_WKS_OS_NAME","KLHST_WKS_OS_VER_MAJOR","KLHST_WKS_OS_VER_MINOR","KLHST_WKS_IP_LONG","KLHST_WKS_CTYPE",
  "KLHST_WKS_STATUS","KLHST_WKS_STATUS_ID","KLHST_WKS_STATUS_MASK","KLHST_WKS_STATUS_HSDP","KLHST_WKS_RTP_STATE","KLHST_WKS_RTP_ERROR_CODE",
  "KLHST_WKS_RTP_AV_VERSION","KLHST_WKS_RTP_AV_BASES_TIME","KLHST_WKS_LAST_FULLSCAN","KLHST_WKS_LAST_VISIBLE","KLHST_WKS_LAST_NAGENT_CONNECTED",
  "KLHST_WKS_LAST_UPDATE","KLHST_WKS_LAST_INFOUDATE","KLHST_WKS_NAG_VERSION","KLHST_WKS_VIRUS_COUNT","KLHST_WKS_UNCURED_COUNT",
  "KLHST_WKS_FROM_UNASSIGNED","KLHST_WKS_RBT_REQUIRED","KLHST_WKS_LAST_SYSTEM_START","KLHST_WKS_CREATED",
  "KLHST_WKS_OS_BUILD_NUMBER","KLHST_WKS_CPU_ARCH","KLHST_WKS_RBT_REQUEST_REASON","KLHST_WKS_RBT_REQUEST_TIME",
  "HST_VM_TYPE","KLHST_MANAGED_OTHER_SERVER","KLHST_WKS_EDR_STATUS","KLHST_WKS_KEEP_CONNECTION"
)
$GroupFields = @("id","name","parentId","grp_full_name","level","hostsNum","childGroupsNum","creationDate","lastUpdate")
$LicenseFields = @("KLLIC_SERIAL","KLLIC_PROD_NAME","KLLIC_KEY_TYPE","KLLIC_CREATION_DATE","KLLIC_LIMIT_DATE","KLLIC_LICENSE_PERIOD","KLLIC_LIC_COUNT",
  "KLLIC_NHOSTS_ASCURRENT","KLLIC_NHOSTS_ASNEXT","KLLIC_USED_BY_ADM_SRV","KLLICSRV_KEY_INSTALLED","KLLIC_APP_ID","KLLIC_MAJ_VER")
$RoleFields = @("nRoleId","wstrRoleName","wstrRoleDisplayName","nInternalUserId","wstrTrusteeDisplayName","wstrUserPrincipalName","nGroupId","wstrGroupName")
$UserFields = @("ul_llTrusteeId","ul_nSplUserId","ul_wstrDisplayName","ul_wstrSamAccountName","ul_wstrPrincipalName","ul_bUser","ul_Builtin","ul_InternalUser")

if ($tlsHook) { [STools.KscTls]::Enable($Server) }
try {
  Write-Host "STools KSC Collector $CollectorVersion → $base" -ForegroundColor Green
  $warnings = New-Object System.Collections.ArrayList
  $policyContents = [ordered]@{}
  Write-Step "Вход"
  $script:session = Start-KscSession
  if (-not $script:session) { throw "KSC не выдал сессию" }
  try {
    Write-Step "Сервер"
    $static = Unwrap (Prop (Invoke-Ksc "HostGroup.GetStaticInfo" @{ pValues = @("KLADMSRV_SERVER_VERSION_ID","KLADMSRV_SERVER_HOSTNAME","KLADMSRV_PRODUCT_FULL_VERSION") }) "PxgRetVal")
    if (-not (Prop $static "KLADMSRV_SERVER_HOSTNAME") -and -not (Prop $static "KLADMSRV_SERVER_VERSION_ID") -and -not (Prop $static "KLADMSRV_PRODUCT_FULL_VERSION")) {
      $static = Unwrap (Prop (Invoke-Ksc "HostGroup.GetStaticInfo" @{ pValues = $null }) "PxgRetVal")
    }
    $domains = @((Prop (Invoke-Ksc "HostGroup.GetDomains" "{}") "PxgRetVal") | Where-Object { $null -ne $_ })

    Write-Step "Группы"
    $ga = (Invoke-Ksc "HostGroup.FindGroups" @{ wstrFilter = ""; vecFieldsToReturn = $GroupFields; vecFieldsToOrder = @(); lMaxLifeTime = 600 }).strAccessor
    $groups = Read-Accessor $ga
    Write-Step ("  Группы: {0}" -f $groups.Count)

    Write-Step "Хосты"
    $ha = (Invoke-Ksc "HostGroup.FindHosts" @{ wstrFilter = ""; vecFieldsToReturn = $HostFields; vecFieldsToOrder = @(); pParams = @{ KLGRP_FIND_FROM_CUR_VS_ONLY = $true }; lMaxLifeTime = 600 }).strAccessor
    $hosts = Read-Accessor $ha
    Write-Step ("  Хосты: {0}" -f $hosts.Count)

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
    Write-Step ("  Политики: {0}" -f $policies.Count)
    $effective = @{}
    foreach ($g in $groups) {
      $gid = AsInt (Prop (Unwrap $g) "id")
      try { $effective[[string]$gid] = @((Prop (Invoke-Ksc "Policy.GetEffectivePoliciesForGroup" @{ nGroupId = $gid }) "PxgRetVal") | Where-Object { $null -ne $_ }) }
      catch { Write-Warning ("политики группы {0}: {1}" -f $gid, $_.Exception.Message); [void]$warnings.Add("политики группы $($gid): $($_.Exception.Message)") }
    }

    if (-not $SkipPolicyContents) {
      Write-Step "Содержимое политик"
      $policyCount = 0
      foreach ($p in $policies) {
        $pv = Unwrap $p
        if (-not (AsBool (Prop $pv "KLPOL_ACTIVE"))) { continue }
        $product = [string](Prop $pv "KLPOL_PRODUCT")
        if ($product -in @("1103", "1093")) { continue }   # не продукт защиты (агент, сервер)
        $policyCount++
        if ($policyCount % 10 -eq 0) { Write-Step ("  политик прочитано: {0}" -f $policyCount) }
        $npolicy = AsInt (Prop $pv "KLPOL_ID")
        $version = [string](Prop $pv "KLPOL_VERSION")
        if ($policyCount -gt $PolicyContentsMaxPolicies) {
          # Пропущенная по лимиту политика остаётся в секции с причиной — POLICY_CONTENT_MISSING её покажет.
          if ($policyCount -eq $PolicyContentsMaxPolicies + 1) {
            Write-Warning ("содержимое политик: больше лимита {0}, часть пропущена" -f $PolicyContentsMaxPolicies)
            [void]$warnings.Add("policy_contents: политик больше лимита $($PolicyContentsMaxPolicies), часть пропущена")
          }
          $policyContents["$npolicy"] = @{ product = $product; version = $version; sections = @{}; errors = @("лимит политик") }
          continue
        }
        try {
          $ssid = (Invoke-Ksc "Policy.GetPolicyContents" @{ nPolicy = $npolicy; nRevisionId = 0; nLifeTime = 0 }).PxgRetVal
          try {
            $names = @((Prop (Invoke-Ksc "SsContents.SS_GetNames" @{ wstrID = $ssid; wstrProduct = $product; wstrVersion = $version }) "PxgRetVal") | Where-Object { $null -ne $_ })
            $sections = [ordered]@{}
            $errors = New-Object System.Collections.ArrayList
            foreach ($sectionName in $names) {
              try {
                $raw = (Invoke-Ksc "SsContents.Ss_Read" @{ wstrID = $ssid; wstrProduct = $product; wstrVersion = $version; wstrSection = $sectionName }).PxgRetVal
                $hidden = Hide-Secrets $sectionName $raw
                $bytes = [Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $hidden -Depth 100 -Compress))
                if ($bytes -gt $PolicyContentsSectionMaxBytes) { [void]$errors.Add("$($sectionName): секция больше лимита") }
                else { $sections[$sectionName] = $hidden }
              } catch { [void]$errors.Add("$($sectionName): $($_.Exception.Message)") }
            }
            $policyContents["$npolicy"] = @{ product = $product; version = $version; sections = $sections; errors = @($errors.ToArray()) }
          } finally {
            Invoke-Ksc "SsContents.Ss_Release" @{ wstrID = $ssid } | Out-Null
          }
        } catch {
          Write-Warning ("содержимое политики {0}: {1}" -f $npolicy, $_.Exception.Message)
          [void]$warnings.Add("policy_contents[$($npolicy)]: $($_.Exception.Message)")
        }
      }
    }

    Write-Step "Задачи"
    $tasks = New-Object System.Collections.ArrayList
    # Задачи не повод терять собранные хосты: отказ на шаге — предупреждение, выгрузка пишется без задач.
    try {
      $it = (Invoke-Ksc "Tasks.ResetTasksIterator" @{ nGroupId = -1; bGroupIdSignificant = $false; strProductName = ""; strVersion = ""; strComponentName = ""; strInstanceId = ""; strTaskName = ""; bIncludeSupergroups = $false }).strTaskIteratorId
      try {
        while ($true) {
          $t = Prop (Invoke-Ksc "Tasks.GetNextTask" @{ strTaskIteratorId = $it }) "pTaskData"
          if ($null -eq $t -or @($t.PSObject.Properties).Count -eq 0) { break }
          $tid = [string](Prop (Unwrap $t) "TASK_UNIQUE_ID")
          # Статистика кладётся в сам объект задачи: у живого KSC он приходит в обёртке @{ type = "params"; value = ... },
          # и лишнее свойство рядом с type/value перестало бы быть обёрткой — задача потерялась бы при разборе.
          if ($tid) { try { (Unwrap $t) | Add-Member -NotePropertyName "statistics" -NotePropertyValue (Prop (Invoke-Ksc "Tasks.GetTaskStatistics" @{ strTask = $tid }) "PxgRetVal") -Force } catch {} }
          # Параметры задачи несут и учётные данные запуска: то же скрытие, что у содержимого политик.
          # Не разобрались — параметры в файл не идут вовсе: неразобранное могло бы унести секрет.
          $taskBody = Unwrap $t
          foreach ($k in @("TASK_ADDITIONAL_PARAMS", "TASK_INFO_PARAMS")) {
            if ($taskBody.PSObject.Properties[$k]) {
              try { $hiddenParams = Hide-Secrets "" $taskBody.$k; $taskBody.$k = $hiddenParams }
              catch {
                $taskBody.$k = "<не разобрано>"
                Write-Warning ("задача {0}, {1}: {2}" -f $tid, $k, $_.Exception.Message); [void]$warnings.Add("задача $($tid), $($k): $($_.Exception.Message)")
              }
            }
          }
          [void]$tasks.Add($t)
          if ($tasks.Count % 50 -eq 0) { Write-Step ("  задач прочитано: {0}" -f $tasks.Count) }
        }
      } finally {
        try { Invoke-Ksc "Tasks.ReleaseTasksIterator" @{ strTaskIteratorId = $it } | Out-Null } catch {}
      }
    } catch { Write-Warning ("задачи: {0}" -f $_.Exception.Message); [void]$warnings.Add("задачи: $($_.Exception.Message)") }
    Write-Step ("  Задачи: {0}" -f $tasks.Count)

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
    Write-Step ("  Лицензии: {0}" -f $licenses.Count)

    Write-Step "Роли и внутренние учётки"
    $roleAssignments = @()
    try { $roleAssignments = Read-SrvView "AdmGroupsAclRolesSrvViewName" $RoleFields }
    catch { Write-Warning ("роли: {0}" -f $_.Exception.Message); [void]$warnings.Add("роли: $($_.Exception.Message)") }
    $internalUsers = @()
    try { $internalUsers = Read-SrvView "GlobalUsersListSrvViewName" $UserFields "(ul_InternalUser = 1)" }
    catch { Write-Warning ("внутренние учётки: {0}" -f $_.Exception.Message); [void]$warnings.Add("внутренние учётки: $($_.Exception.Message)") }

    Write-Step "Двухэтапная проверка"
    $twoFactor = $null
    try { $twoFactor = (Invoke-Ksc "TotpGlobalSettings.Get2FaRequiredForAll" "{}").PxgRetVal }
    catch { Write-Warning ("2FA: {0}" -f $_.Exception.Message); [void]$warnings.Add("2FA: $($_.Exception.Message)") }
    $security = @{ two_factor_required_for_all = $twoFactor }

    Write-Step "Сертификаты"
    # Из контейнера берём только CPublic — приватная часть и прочие поля в выгрузку не идут.
    # Отказ в правах (HTTP 403) — отказ на весь метод: секция остаётся пустой. Любая другая ошибка функции
    # значит, что сертификата для этого назначения нет: функция пропускается, остальные собираются.
    $serverCerts = @{}
    for ($n = 1; $n -le 4; $n++) {
      try {
        $c = Unwrap (Prop (Invoke-Ksc "CertPoolCtrl.GetCertificateInfo" @{ nVServerId = -1; nFunction = $n }) "PxgRetVal")
        $public = Prop $c "CPublic"
        if ($null -ne $public) { $serverCerts["$n"] = @{ CPublic = $public } }
      } catch {
        if ((HttpStatus $_) -eq 403) {
          $serverCerts = @{}
          Write-Warning ("сертификаты: {0}" -f $_.Exception.Message); [void]$warnings.Add("сертификаты: нет прав на CertPoolCtrl.GetCertificateInfo")
          break
        }
        Write-Warning ("сертификат, функция {0}: {1}" -f $n, $_.Exception.Message); [void]$warnings.Add("сертификат, функция $($n): $($_.Exception.Message)")
      }
    }

    Write-Step "Подчинённые серверы"
    $secondaryServers = @()
    try { $secondaryServers = @((Prop (Invoke-Ksc "ServerHierarchy.GetChildServers" @{ nGroupId = -1 }) "PxgRetVal") | Where-Object { $null -ne $_ }) }
    catch { Write-Warning ("иерархия: {0}" -f $_.Exception.Message); [void]$warnings.Add("иерархия: $($_.Exception.Message)") }

    Write-Step "Точки распространения"
    $updateAgents = @()
    try { $updateAgents = @((Prop (Invoke-Ksc "UaControl.GetUpdateAgentsList" "{}") "pUasArr") | Where-Object { $null -ne $_ }) }
    catch { Write-Warning ("точки распространения: {0}" -f $_.Exception.Message); [void]$warnings.Add("точки распространения: $($_.Exception.Message)") }
  } finally {
    try { Invoke-Ksc "Session.EndSession" "{}" | Out-Null } catch {}
  }

  $serverName = [string](Prop $static "KLADMSRV_SERVER_HOSTNAME")
  if (-not $serverName) { $serverName = $Server }
  $export = [ordered]@{
    format = $FormatVersion
    server = @{ name = $serverName; version = [string](Prop $static "KLADMSRV_PRODUCT_FULL_VERSION"); collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); collector = "powershell"; collector_version = $CollectorVersion; user = $User; host = $Server; warnings = @($warnings.ToArray()) }
    groups = $groups; hosts = $hosts; host_products = $products; host_components = $components
    policies = $policies; effective_policies = $effective; tasks = $tasks.ToArray(); licenses = $licenses.ToArray()
    static = $static; domains = $domains
    role_assignments = @($roleAssignments); internal_users = @($internalUsers); security = $security
    server_certs = $serverCerts; secondary_servers = @($secondaryServers); update_agents = @($updateAgents)
    policy_contents = $policyContents
  }

  # Имя сервера пришло из ответа KSC: в имя файла — только латиница, цифры, точка, дефис и подчёркивание.
  $safeName = $serverName -creplace '[^A-Za-z0-9._-]', '_'
  $defaultName = "ksc-{0}-{1}.json.gz" -f $safeName, (Get-Date -Format "yyyyMMdd-HHmm")
  if (-not $OutputPath) { $OutputPath = $defaultName }
  # Указан каталог, а не файл — кладём в него файл с именем по умолчанию.
  elseif ($OutputPath -match '[\\/]$' -or (Test-Path -LiteralPath $OutputPath -PathType Container)) { $OutputPath = Join-Path $OutputPath $defaultName }
  if (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $PWD.ProviderPath $OutputPath }
  Write-Step "Запись $OutputPath"
  $json = $export | ConvertTo-Json -Depth 100 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $out = [System.IO.File]::Create($OutputPath)
  try {
    $gz = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Dispose()
  } finally { $out.Dispose() }
  Write-Host ("Готово: хостов {0}, групп {1}, политик {2}, задач {3}, размер {4:N0} байт" -f $hosts.Count, $groups.Count, $policies.Count, $tasks.Count, (Get-Item $OutputPath).Length) -ForegroundColor Green
  Write-Host "Загрузите файл в STools: Антивирус → Настройки и данные → Загрузить выгрузку."
  if ($DeleteConfigAfterRun -and $ConfigPath) {
    try { Remove-Item -LiteralPath $ConfigPath -Force; Write-Host "Файл настроек удалён: $ConfigPath" }
    catch { Write-Warning ("файл настроек не удалён ({0}): удалите его вручную" -f $_.Exception.Message) }
  }
} catch {
  # Где оборвалось: шаг, строка скрипта и стек — чтобы отказ можно было разобрать по одному выводу.
  Write-Host ""
  Write-Host ("Сбор прерван на шаге «{0}»: {1}" -f $script:stage, $_.Exception.Message) -ForegroundColor Red
  $pos = $_.InvocationInfo
  if ($pos -and $pos.ScriptLineNumber) { Write-Host ("  строка {0}: {1}" -f $pos.ScriptLineNumber, ([string]$pos.Line).Trim()) -ForegroundColor Red }
  if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
  Write-Host "Файл выгрузки не записан." -ForegroundColor Red
  throw
} finally {
  if ($tlsHook) { [STools.KscTls]::Restore() }
}
