<#
.SYNOPSIS
  STools — сборщик Active Directory: выгрузка домена (формат stools-ad/1) и данные
  центров сертификации (формат stools-ad-ca/1).

.DESCRIPTION
  Запускается на машине в домене с модулем ActiveDirectory (RSAT). Ничего не
  анализирует и не меняет.

  Выгрузка AD: объекты, дескрипторы безопасности (в том числе привилегированных
  групп, их участников, Administrator и krbtgt), ссылки GPO, файлы GPO из SYSVOL
  (GptTmpl.inf; Registry.pol — только значения белого списка; настройки GPP —
  без паролей; аудит; скрипты) и права на папки GPO и файлы их скриптов,
  шаблоны сертификатов, центры сертификации и контейнеры PKI, политики выдачи,
  доверенные домены, настройки домена и леса, политики паролей (PSO), зоны DNS,
  сайты и подсети — один JSON (gzip), ad-<NETBIOS>-<дата>.json.gz. Хватает
  прав чтения каталога; PSO видны только администратору домена.

  Данные ЦС (их по LDAP не прочитать, STools сам их не собирает):
    ca  — флаги и права каждого ЦС (certutil, при отказе — удалённый реестр);
          нужны права администратора ЦС или локального администратора сервера ЦС;
    dc  — состояние каждого контроллера домена: удалённый реестр (привязка сертификатов, NTLM,
          подпись LDAP, протоколы SCHANNEL, сборка ОС) и CIM по WSMan, при отказе — по DCOM
          (SMB, службы Spooler и WebClient, время загрузки); нужны права администратора на
          контроллерах;
    web — ответ веб-выдачи ЦС на запрос без учётных данных (порты 80/443).
  Пишутся отдельным файлом adca-<NETBIOS>-<дата>.json.gz. Ошибка по отдельному
  серверу пишется в запись этого сервера и сбор не прерывает.

  Оба файла загружаются в STools → Active Directory → Настройки и данные тем же
  полем «Загрузить выгрузку».

  Без параметров (или только с -Server и -Yes) скрипт показывает меню, печатает
  план (какие серверы и что будет прочитано) и спрашивает подтверждение.

.PARAMETER Mode
  Menu — меню и подтверждение; All — выгрузка AD и данные ЦС; AD — только
  выгрузка AD; CA — только данные ЦС. С All, AD и CA вопросов нет.
  Без -Mode: если указан -SkipComputerAcl, -SkipSysvol или -OutputPath — AD
  (как команды сборщика 1.x); если указан -Sections — CA, а вместе с
  -SkipComputerAcl или -SkipSysvol — All; иначе — Menu.

.PARAMETER Sections
  Разделы данных ЦС для -Mode All и CA: ca, dc, web (по умолчанию все).

.PARAMETER OutputPath
  Файл или каталог для результата. По умолчанию — текущий каталог. Если
  пишутся оба файла, а указан файл, в него идёт выгрузка AD, а данные ЦС — в
  тот же каталог под именем по умолчанию.

.PARAMETER Server
  Контроллер домена для запросов LDAP (по умолчанию — ближайший).

.PARAMETER SkipComputerAcl
  Не читать дескрипторы компьютеров (быстрее; проверка ACL компьютеров
  тогда пуста).

.PARAMETER SkipSysvol
  Не читать SYSVOL: ни файлов GPO, ни прав на их папки (проверки по
  содержимому GPO пусты, блока gpo в выгрузке нет).

.PARAMETER Yes
  Не спрашивать подтверждение после плана (для режима меню).

.EXAMPLE
  .\STools-AD-Collector.ps1
  .\STools-AD-Collector.ps1 -Mode All -Server dc01.corp.local -OutputPath C:\Temp\
  .\STools-AD-Collector.ps1 -Mode AD -SkipComputerAcl
  .\STools-AD-Collector.ps1 -Mode CA -Sections ca,web
#>
#requires -Modules ActiveDirectory
[CmdletBinding()]
param(
  [ValidateSet("Menu", "All", "AD", "CA")]
  [string]$Mode = "Menu",
  [string[]]$Sections,
  [string]$OutputPath,
  [string]$Server,
  [switch]$SkipComputerAcl,
  [switch]$SkipSysvol,
  [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$FormatVersion = "stools-ad/1"
$CaFormatVersion = "stools-ad-ca/1"
$CollectorVersion = "2.3"
# Критичные объекты: группы домена (Domain Admins, Cert Publishers, Schema Admins, Enterprise Admins,
# Group Policy Creator Owners, Key Admins, Enterprise Key Admins, Allowed RODC Password Replication Group),
# встроенные (Administrators, Account, Server, Print, Backup Operators, Replicator), DnsAdmins по имени.
$CriticalGroupRids = @(512, 517, 518, 519, 520, 526, 527, 571)
$CriticalBuiltinRids = @(544, 548, 549, 550, 551, 552)
$CriticalGroupNames = @("DnsAdmins")
$CriticalMembersLimit = 5000
# Файлы GPO из SYSVOL (спека §3.1, список — как GPO_FILES в gpo_files.py): имя (часть/файл) → путь относительно
# папки GPO. Services бывают только у компьютера, Drives — только у пользователя. Файл больше потолка не читается.
$GpoFiles = [ordered]@{
  "machine/Registry.pol" = "Machine\Registry.pol"
  "user/Registry.pol" = "User\Registry.pol"
  "machine/Groups.xml" = "Machine\Preferences\Groups\Groups.xml"
  "machine/Services.xml" = "Machine\Preferences\Services\Services.xml"
  "machine/ScheduledTasks.xml" = "Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
  "machine/DataSources.xml" = "Machine\Preferences\DataSources\DataSources.xml"
  "machine/Printers.xml" = "Machine\Preferences\Printers\Printers.xml"
  "machine/Files.xml" = "Machine\Preferences\Files\Files.xml"
  "user/Groups.xml" = "User\Preferences\Groups\Groups.xml"
  "user/ScheduledTasks.xml" = "User\Preferences\ScheduledTasks\ScheduledTasks.xml"
  "user/DataSources.xml" = "User\Preferences\DataSources\DataSources.xml"
  "user/Drives.xml" = "User\Preferences\Drives\Drives.xml"
  "user/Printers.xml" = "User\Preferences\Printers\Printers.xml"
  "user/Files.xml" = "User\Preferences\Files\Files.xml"
  "machine/audit.csv" = "Machine\Microsoft\Windows NT\Audit\audit.csv"
  "machine/scripts.ini" = "Machine\Scripts\scripts.ini"
  "machine/psscripts.ini" = "Machine\Scripts\psscripts.ini"
  "user/scripts.ini" = "User\Scripts\scripts.ini"
  "user/psscripts.ini" = "User\Scripts\psscripts.ini"
}
$MaxGpoFile = 4 * 1024 * 1024

$ad = @{}
if ($Server) { $ad["Server"] = $Server }

# Ход работы: у каждой строки — время от начала сбора. Строка без отступа открывает шаг (его имя
# попадёт в сообщение об ошибке), с отступом — уточняет текущий: счётчик или итог шага.
$script:started = Get-Date
$script:stage = ""
function Write-Step([string]$text) {
  if (-not $text.StartsWith(" ")) { $script:stage = $text }
  $t = (Get-Date) - $script:started
  Write-Host ("  [{0:00}:{1:00}] {2}" -f [int][math]::Floor($t.TotalMinutes), $t.Seconds, $text) -ForegroundColor Cyan
}

$script:warnings = New-Object System.Collections.ArrayList
function Add-Warning([string]$text) {
  Write-Warning $text
  [void]$script:warnings.Add($text)
}

function ToBase64Sd($sd) {
  if ($null -eq $sd) { return $null }
  try {
    if ($sd -is [byte[]]) { return [Convert]::ToBase64String($sd) }
    return [Convert]::ToBase64String($sd.GetSecurityDescriptorBinaryForm())
  } catch { return $null }
}

function AsList($value) {
  # Запятая мешает PowerShell развернуть массив на выходе из функции. В
  # Windows PowerShell 5.1 это помогает не всегда: пустой список может уйти
  # в JSON как null или {}, одиночный — строкой; анализатор принимает все
  # эти варианты.
  if ($null -eq $value) { return ,@() }
  if ($value -is [string]) { return ,@($value) }
  return ,@($value | ForEach-Object { [string]$_ })
}

function AsInt64($value) {
  if ($null -eq $value) { return $null }
  try { return [int64]$value } catch { return $null }
}

function AsInt($value) {
  if ($null -eq $value) { return $null }
  try { return [int]$value } catch { return $null }
}

function AsStr($value) {
  if ($null -eq $value) { return $null }
  return [string]$value
}

# REG_DWORD приходит из реестра как Int32 со знаком; флаги пишутся без знака.
function AsDword($value) {
  if ($null -eq $value) { return $null }
  if ($value -is [int]) { return [int64][BitConverter]::ToUInt32([BitConverter]::GetBytes($value), 0) }
  try { return [int64]$value } catch { return $null }
}

# Двоичный SID (securityIdentifier доверенного домена) → строка S-1-…
function SidFromBytes([byte[]]$bytes) {
  $authority = [int64]0
  for ($i = 2; $i -lt 8; $i++) { $authority = $authority * 256 + $bytes[$i] }
  $parts = @("S", $bytes[0], $authority)
  for ($i = 0; $i -lt $bytes[1]; $i++) { $parts += [BitConverter]::ToUInt32($bytes, 8 + 4 * $i) }
  return $parts -join "-"
}

# Текст ошибки для записи сервера: самое внутреннее исключение, без обёртки «Exception calling …».
function ErrorText($err) {
  $ex = $err.Exception
  while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
  return $ex.Message
}

function SidString($value) {
  if ($null -eq $value) { return $null }
  try { return $value.Value } catch { return [string]$value }
}

# SID атрибута со строковым синтаксисом (ms-DS-CreatorSID) модуль отдаёт байтами, с синтаксисом SID — объектом.
function AnySid($value) {
  if ($value -is [byte[]]) { return SidFromBytes $value }
  return SidString $value
}

function SidList($value) {
  if ($null -eq $value) { return ,@() }
  return ,@($value | ForEach-Object { AnySid $_ })
}

# Время AD → ISO 8601 UTC; формат не зависит от языковых настроек Windows.
function IsoTime($value) {
  if ($null -eq $value) { return $null }
  return ([datetime]$value).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function AsBool($value) {
  if ($null -eq $value) { return $null }
  return [bool]$value
}

# Время последней резервной копии домена: резервное копирование меняет dSASignature корня, время
# изменения — в msDS-ReplAttributeMetaData (XML на каждый атрибут, у значений бывает завершающий \0).
# Записи dSASignature нет — $null.
function Get-LastBackup([string[]]$metadata) {
  foreach ($item in @($metadata)) {
    if (-not $item) { continue }
    $m = [regex]::Match($item, '<pszAttributeName>\s*([^<]*?)\s*</pszAttributeName>.*?<ftimeLastOriginatingChange>\s*([^<]*?)\s*</ftimeLastOriginatingChange>', 'Singleline')
    if (-not $m.Success -or $m.Groups[1].Value -cne "dSASignature") { continue }
    try {
      $t = [DateTimeOffset]::Parse($m.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
    } catch { return $null }
    return $t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
  }
  return $null
}

# Режим динамических обновлений зоны из dNSProperty: заголовок 20 байт (DataLength, NameLength, Flag,
# Version, Id), затем данные; у записи с Id 2 — первый байт данных: 0 — нет, 1 — любые, 2 — безопасные.
function Get-DnsAllowUpdate([byte[][]]$properties) {
  foreach ($p in @($properties)) {
    if ($null -eq $p -or $p.Length -lt 20) { continue }
    $length = [BitConverter]::ToUInt32($p, 0)
    $id = [BitConverter]::ToUInt32($p, 16)
    if ($id -eq 2 -and $length -gt 0 -and $p.Length -gt 20) { return [int]$p[20] }
  }
  return $null
}

# DN-Binary «B:<длина>:<hex>:<DN>» → DN; в самом DN двоеточие допустимо.
function Get-DnBinaryDn([string]$value) {
  $parts = $value.Split([char[]]":", 4)
  if ($parts.Count -eq 4 -and $parts[0] -eq "B") { return $parts[3] }
  return $value
}

# ---- Файлы GPO из SYSVOL (спека §3.1): разбор — как в gpo_files.py LDAP-сборщика 1.2 ----
# Значения паролей отсюда не выходят: у GPP остаётся факт cpassword, у автологона — пустая строка
# вместо DefaultPassword; из Registry.pol — только значения белого списка.

# Registry.pol (PReg): заголовок «PReg» и версия 1, затем записи [key;value;type;size;data] в UTF-16LE.
# Данные могут содержать «;» и «]», поэтому разбор идёт по размерам, а не по разделителям. Команды
# удаления (**del.X, **delvals. и прочие «**») пропускаются. Битый файл — исключение.
# Данные: REG_SZ и REG_EXPAND_SZ — строка, REG_DWORD — число, REG_MULTI_SZ — список строк, прочее — $null.
function Read-RegistryPol([byte[]]$bytes) {
  $n = $bytes.Length
  if ($n -lt 8 -or [Text.Encoding]::ASCII.GetString($bytes, 0, 4) -cne "PReg" -or [BitConverter]::ToUInt32($bytes, 4) -ne 1) {
    throw "не файл Registry.pol (нет заголовка PReg версии 1)"
  }
  # Разделитель «[», «;» или «]» (UTF-16LE) на смещении $at; отдаёт смещение после него.
  function Step-PolToken([int64]$at, [char]$c) {
    if ($at + 2 -gt $n -or $bytes[$at] -ne [int]$c -or $bytes[$at + 1] -ne 0) { throw ("Registry.pol повреждён: на смещении {0} нет «{1}»" -f $at, $c) }
    return $at + 2
  }
  # Смещение завершающего нуля строки UTF-16LE, начатой на $at: первый нулевой байт на чётном от $at
  # смещении, за которым тоже ноль. Поиск байта — [Array]::IndexOf, без цикла по байтам в PowerShell.
  function Find-PolNul([int64]$at) {
    $i = [int]$at
    while ($true) {
      $i = [Array]::IndexOf($bytes, [byte]0, $i)
      if ($i -lt 0 -or $i + 2 -gt $n) { throw "Registry.pol обрезан" }
      if (($i - $at) % 2 -eq 0 -and $bytes[$i + 1] -eq 0) { return [int64]$i }
      $i++
    }
  }
  $utf16 = [Text.Encoding]::Unicode
  $out = New-Object System.Collections.Generic.List[object]
  $pos = [int64]8
  while ($pos -lt $n) {
    $pos = Step-PolToken $pos "["
    $end = Find-PolNul $pos
    $key = $utf16.GetString($bytes, $pos, $end - $pos)
    $pos = Step-PolToken ($end + 2) ";"
    $end = Find-PolNul $pos
    $value = $utf16.GetString($bytes, $pos, $end - $pos)
    $pos = Step-PolToken ($end + 2) ";"
    if ($pos + 4 -gt $n) { throw "Registry.pol обрезан" }
    $type = [int64][BitConverter]::ToUInt32($bytes, $pos)
    $pos = Step-PolToken ($pos + 4) ";"
    if ($pos + 4 -gt $n) { throw "Registry.pol обрезан" }
    $size = [int64][BitConverter]::ToUInt32($bytes, $pos)
    $pos = Step-PolToken ($pos + 4) ";"
    if ($pos + $size -gt $n) { throw "Registry.pol обрезан" }
    $start = $pos
    $pos = Step-PolToken ($pos + $size) "]"
    if ($value.StartsWith("**", [StringComparison]::Ordinal)) { continue }
    $data = $null
    if ($type -eq 1 -or $type -eq 2) {
      $data = $utf16.GetString($bytes, $start, $size).TrimEnd([char]0)
    } elseif ($type -eq 4) {
      if ($size -eq 4) { $data = [int64][BitConverter]::ToUInt32($bytes, $start) }
    } elseif ($type -eq 7) {
      $text = $utf16.GetString($bytes, $start, $size).TrimEnd([char]0)
      $data = [string[]]@(if ($text) { $text.Split([char]0) })
    }
    $out.Add(@{ key = $key; value = $value; type = $type; data = $data })
  }
  $out.ToArray()
}

# Белый список Registry.pol (спека §3.1, как keep_registry в gpo_files.py): ключ → имена значений;
# $null — все значения ключа. Регистр не важен, обратная косая черта по краям ключа — тоже.
function Test-KeepRegistry([string]$key, [string]$value) {
  $keep = @{
    "Software\Policies\Microsoft\Windows NT\DNSClient" = @("EnableMultiCast")
    "Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" = $null
    "Software\Policies\Microsoft\Windows\WindowsUpdate" = @("WUServer", "SetProxyBehaviorForUpdateDetection", "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection")
    "Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" = @("EnableScriptBlockLogging")
    "Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" = @("EnableModuleLogging")
    "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" = @("AutoAdminLogon", "DefaultUserName", "DefaultPassword")
    "System\CurrentControlSet\Control\Lsa" = @("LmCompatibilityLevel", "NoLMHash", "RestrictAnonymous", "EveryoneIncludesAnonymous", "LimitBlankPasswordUse")
    "System\CurrentControlSet\Services\NTDS\Parameters" = @("LDAPServerIntegrity")
    "System\CurrentControlSet\Services\Netlogon\Parameters" = @("RefusePasswordChange")
    "Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" = @("SecurityLevel")
  }
  $k = $key.Trim([char]'\')
  if (-not $keep.ContainsKey($k)) { return $false }
  return ($null -eq $keep[$k]) -or ($keep[$k] -contains $value)
}

# Пароль автологона не покидает домен: данные DefaultPassword заменяются пустой строкой, остаётся факт.
function Protect-RegistryValue($v) {
  if ($v.key.Trim([char]'\') -eq "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -and $v.value -eq "DefaultPassword") { $v.data = "" }
  return $v
}

# Настройки GPP (Groups.xml и др.): запись — любой элемент с дочерним Properties. Текст с DOCTYPE отвергается
# до разбора (сущности, «миллиард смехов»), внешние ресурсы не загружаются. Значение cpassword не копируется:
# в записи только факт его наличия.
function Read-GppFile([string]$file, [string]$scope, [string]$xmlText) {
  if ($xmlText -match '(?i)<!doctype') { throw ("{0}: XML с DOCTYPE не разбирается" -f $file) }
  $settings = New-Object System.Xml.XmlReaderSettings
  $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver = $null
  $doc = New-Object System.Xml.XmlDocument
  $doc.XmlResolver = $null
  $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($xmlText.TrimStart([char]0xFEFF))), $settings)
  try { $doc.Load($reader) }
  catch {
    $ex = $_.Exception
    while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
    throw ("{0}: XML не разобран ({1})" -f $file, $ex.Message)
  } finally { $reader.Dispose() }
  # Свойства узлов — только методами get_*: адаптер XML в PowerShell подменяет .Name, .ChildNodes и прочие
  # одноимёнными атрибутами и дочерними элементами (у Member есть атрибут name).
  $elementType = [System.Xml.XmlNodeType]::Element
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($el in $doc.SelectNodes("//*")) {
    $props = $null
    foreach ($c in $el.get_ChildNodes()) { if ($c.get_NodeType() -eq $elementType -and $c.get_Name() -ceq "Properties") { $props = $c; break } }
    if ($null -eq $props) { continue }
    $members = @()
    foreach ($c in $props.get_ChildNodes()) {
      if ($c.get_NodeType() -ne $elementType -or $c.get_Name() -cne "Members") { continue }
      foreach ($m in $c.get_ChildNodes()) {
        if ($m.get_NodeType() -eq $elementType -and $m.get_Name() -ceq "Member") {
          $members += [ordered]@{ name = $m.GetAttribute("name"); sid = $m.GetAttribute("sid"); action = $m.GetAttribute("action") }
        }
      }
      break
    }
    $user = ""
    foreach ($a in "userName", "accountName", "runAs", "username") { if ($props.GetAttribute($a)) { $user = $props.GetAttribute($a); break } }
    $path = ""
    foreach ($a in "path", "fromPath") { if ($props.GetAttribute($a)) { $path = $props.GetAttribute($a); break } }
    $out.Add([ordered]@{
      scope = $scope; file = $file; kind = $el.get_Name(); name = $el.GetAttribute("name"); user = $user
      cpassword = [bool]$props.GetAttribute("cpassword"); action = $props.GetAttribute("action"); members = [object[]]$members
      group_sid = $props.GetAttribute("groupSid"); group_name = $props.GetAttribute("groupName"); path = $path
    })
  }
  $out.ToArray()
}

# audit.csv расширенной политики аудита: {subcategory: GUID в нижнем регистре без скобок, setting: 0–3}.
# Строки параметров (Option:…) без GUID или с нечисловым значением пропускаются.
function Read-AuditCsv([string]$text) {
  $text = $text.TrimStart([char]0xFEFF)
  if (-not $text.Trim()) { return }
  try {
    $first = ($text -split "\r\n|\n|\r", 2)[0]
    # Столбцы — по строке заголовка (у файла без строк данных ConvertFrom-Csv их не покажет).
    $columns = @(@($first, $first) | ConvertFrom-Csv)[0].PSObject.Properties | ForEach-Object { $_.Name }
    $rows = @($text | ConvertFrom-Csv)
  } catch { throw ("audit.csv не разобран ({0})" -f $_.Exception.Message) }
  if (-not ($columns -ccontains "Subcategory GUID" -and $columns -ccontains "Setting Value")) {
    throw "audit.csv: нет столбцов «Subcategory GUID» и «Setting Value»"
  }
  foreach ($row in $rows) {
    $guid = ([string]$row."Subcategory GUID").Trim().Trim([char[]]"{}").ToLowerInvariant()
    $setting = 0
    if (-not [int]::TryParse(([string]$row."Setting Value").Trim(), [ref]$setting)) { continue }
    if ($guid) { [ordered]@{ subcategory = $guid; setting = $setting } }
  }
}

# scripts.ini и psscripts.ini: секции Logon, Logoff, Startup, Shutdown, ключи «<n>CmdLine» и «<n>Parameters».
# Секции и строки — как parse_inf в gpo_files.py: «;» в начале строки — комментарий, строки без «=» пропускаются.
function Read-ScriptsIni([string]$text, [string]$scope) {
  $sections = [ordered]@{}
  $current = $null
  foreach ($raw in ($text.TrimStart([char]0xFEFF) -split "\r\n|\n|\r")) {
    $line = $raw.Trim()
    if ($line.StartsWith("[") -and $line.EndsWith("]") -and $line.Length -ge 2) {
      $name = $line.Substring(1, $line.Length - 2).Trim().ToLowerInvariant()
      if (-not $sections.Contains($name)) { $sections[$name] = [ordered]@{} }
      $current = $sections[$name]
      continue
    }
    $eq = $line.IndexOf("=")
    if ($null -eq $current -or $eq -lt 0 -or $line.StartsWith(";")) { continue }
    $current[$line.Substring(0, $eq).Trim()] = $line.Substring($eq + 1).Trim()
  }
  foreach ($phase in $sections.Keys) {
    if (@("logon", "logoff", "startup", "shutdown") -notcontains $phase) { continue }
    $entries = @{}
    foreach ($key in $sections[$phase].Keys) {
      if ($key -match '^(\d+)(cmdline|parameters)$') {
        $n = [decimal]$Matches[1]
        if (-not $entries.ContainsKey($n)) { $entries[$n] = @{} }
        $entries[$n][$Matches[2].ToLowerInvariant()] = $sections[$phase][$key]
      }
    }
    foreach ($n in @($entries.Keys | Sort-Object)) {
      $command = $(if ($entries[$n].ContainsKey("cmdline")) { $entries[$n]["cmdline"] } else { "" })
      if (-not $command) { continue }
      $parameters = $(if ($entries[$n].ContainsKey("parameters")) { $entries[$n]["parameters"] } else { "" })
      [ordered]@{ scope = $scope; phase = $phase; command = $command; parameters = $parameters }
    }
  }
}

# Кто, кроме владельца, может писать в файл или папку SYSVOL: SID разрешающих записей с правом записи
# (Write, Modify, FullControl и любые их части записи данных), сменой прав или владельца, общими правами
# записи. Записи только для наследования (InheritOnly) к самому объекту не относятся. Повторы убираются.
function Get-PathWriters([string]$path) {
  $acl = Get-Acl -LiteralPath $path
  $sidType = [System.Security.Principal.SecurityIdentifier]
  $owner = $null
  try { $owner = [string]$acl.GetOwner($sidType).Value } catch { }
  $fsr = [System.Security.AccessControl.FileSystemRights]
  # 0x40000000 — GENERIC_WRITE, 0x10000000 — GENERIC_ALL: так записаны права, наследуемые от шаблона.
  $mask = [int64]($fsr::WriteData -bor $fsr::AppendData -bor $fsr::ChangePermissions -bor $fsr::TakeOwnership) -bor 0x40000000 -bor 0x10000000
  $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
  $writers = New-Object System.Collections.Generic.List[string]
  foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($rule.PropagationFlags -band $inheritOnly) -eq $inheritOnly) { continue }
    if (([int64][int]$rule.FileSystemRights -band $mask) -eq 0) { continue }
    $sid = [string]$rule.IdentityReference.Value
    if ($sid -and $sid -ne $owner -and -not $writers.Contains($sid)) { $writers.Add($sid) }
  }
  $writers.ToArray()
}

# Байты файла SYSVOL → текст: UTF-16 по BOM, иначе UTF-8 (BOM снимается) — как _decode_inf LDAP-сборщика.
function ConvertFrom-SysvolBytes([byte[]]$bytes) {
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2) }
  return [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
}

# Папка GPO в SYSVOL: GptTmpl.inf (текстом, для блока sysvol) и запись блока gpo — те же поля, что у
# LDAP-сборщика, плюс acl. Читаются только файлы, которые показал листинг; отказ на файле — строка в notes
# записи, сбор продолжается. acl — права на папку GPO и на файлы её скриптов; $null — права не прочитаны.
function Read-GpoFiles([string]$base) {
  $registry = New-Object System.Collections.Generic.List[object]
  $gpp = New-Object System.Collections.Generic.List[object]
  $audit = New-Object System.Collections.Generic.List[object]
  $scripts = New-Object System.Collections.Generic.List[object]
  $notes = New-Object System.Collections.Generic.List[string]
  $acl = $null
  $tmpl = $null
  $result = { @{ tmpl = $tmpl; data = [ordered]@{ registry = $registry.ToArray(); gpp = $gpp.ToArray(); audit = $audit.ToArray(); scripts = $scripts.ToArray(); acl = $acl; notes = [string[]]$notes.ToArray() } } }

  # Один листинг папки GPO; файлы ищутся по относительному пути без учёта регистра.
  $present = @{}
  $listErrors = @()
  try {
    $gpoRoot = (Get-Item -LiteralPath $base -Force).FullName.TrimEnd([char[]]"\/")
    $items = @(Get-ChildItem -LiteralPath $gpoRoot -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable listErrors)
  } catch {
    $notes.Add(("папка GPO не прочитана ({0})" -f $_.Exception.Message))
    return (& $result)
  }
  foreach ($e in @($listErrors)) {
    $where = [string]$e.TargetObject
    if ($where.StartsWith($gpoRoot, [StringComparison]::OrdinalIgnoreCase)) { $where = $where.Substring($gpoRoot.Length).TrimStart([char[]]"\/") }
    $notes.Add(("{0}: папка не прочитана ({1})" -f $where, $e.Exception.Message))
  }
  foreach ($f in $items) {
    $rel = $f.FullName.Substring($gpoRoot.Length).TrimStart([char[]]"\/").Replace("/", "\")
    $present[$rel.ToLowerInvariant()] = @{ rel = $rel; file = $f }
  }
  # Байты файла по пути из $GpoFiles; $null — файла нет, он не прочитан или больше потолка (последние два — в notes).
  function Get-GpoBytes([string]$rel) {
    $hit = $present[$rel.ToLowerInvariant()]
    if ($null -eq $hit) { return $null }
    if ($hit.file.Length -gt $MaxGpoFile) { $notes.Add(("{0}: файл больше {1} МБ, не разобран" -f $rel, ($MaxGpoFile / 1MB))); return $null }
    try { return ,[System.IO.File]::ReadAllBytes($hit.file.FullName) }
    catch { $notes.Add(("{0}: не прочитан ({1})" -f $rel, (ErrorText $_))); return $null }
  }

  $tmplRel = "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
  $content = Get-GpoBytes $tmplRel
  if ($null -ne $content -and $content.Length -gt 0) {
    try { $tmpl = ConvertFrom-SysvolBytes $content } catch { $notes.Add(("{0}: {1}" -f $tmplRel, $_.Exception.Message)) }
  }
  foreach ($name in $GpoFiles.Keys) {
    $rel = $GpoFiles[$name]
    $content = Get-GpoBytes $rel
    if ($null -eq $content) { continue }
    $scope, $file = $name -split "/", 2
    $kind = $file.ToLowerInvariant()
    try {
      if ($kind.EndsWith(".pol")) {
        foreach ($v in @(Read-RegistryPol $content)) {
          if (-not (Test-KeepRegistry $v.key $v.value)) { continue }
          $v = Protect-RegistryValue $v
          $registry.Add([ordered]@{ scope = $scope; key = $v.key; value = $v.value; type = $v.type; data = $v.data })
        }
      } elseif ($kind -eq "audit.csv") {
        foreach ($r in @(Read-AuditCsv (ConvertFrom-SysvolBytes $content))) { $audit.Add($r) }
      } elseif ($kind.EndsWith(".ini")) {
        foreach ($r in @(Read-ScriptsIni (ConvertFrom-SysvolBytes $content) $scope)) { $scripts.Add($r) }
      } elseif ($kind.EndsWith(".xml")) {
        foreach ($r in @(Read-GppFile $file $scope (ConvertFrom-SysvolBytes $content))) { $gpp.Add($r) }
      } else { $notes.Add(("{0}: неизвестный тип файла" -f $rel)) }
    } catch { $notes.Add(("{0}: {1}" -f $rel, $_.Exception.Message)) }
  }

  # Права: папка GPO (path "") и файлы скриптов, лежащие в ней: имя без пути — в Scripts\<фаза> своей части,
  # полный путь — если он ведёт внутрь папки GPO. Скрипты вне папки GPO здесь не проверяются. Отказ по папке —
  # acl $null; отказ по скрипту — пропуск только этого скрипта (пометка), запись папки остаётся.
  $records = New-Object System.Collections.Generic.List[object]
  try { $records.Add([ordered]@{ path = ""; writers = [string[]]@(Get-PathWriters $gpoRoot) }) }
  catch { $notes.Add(("права SYSVOL не прочитаны ({0})" -f $_.Exception.Message)); $records = $null }
  if ($null -ne $records) {
    $done = @{}
    foreach ($s in $scripts) {
      # Кавычки вокруг команды снимаются; «полный путь» — по началу строки, а не [IO.Path]::IsPathRooted:
      # в .NET Framework тот бросает исключение на кавычках, <, > и |.
      $command = ([string]$s["command"]).Trim()
      if ($command.Length -ge 2 -and $command.StartsWith('"') -and $command.EndsWith('"')) { $command = $command.Substring(1, $command.Length - 2) }
      $where = $command
      try {
        $rel = $null
        if ($command -match '^([\\/]|[A-Za-z]:)') {
          if ($command.Length -gt $gpoRoot.Length + 1 -and $command.StartsWith($gpoRoot, [StringComparison]::OrdinalIgnoreCase) -and
              ($command[$gpoRoot.Length] -eq [char]'\' -or $command[$gpoRoot.Length] -eq [char]'/')) { $rel = $command.Substring($gpoRoot.Length + 1) }
        } else {
          $rel = "{0}\Scripts\{1}\{2}" -f $(if ($s["scope"] -eq "machine") { "Machine" } else { "User" }), $s["phase"], $command
        }
        if ($null -eq $rel) { continue }
        $hit = $present[$rel.Replace("/", "\").ToLowerInvariant()]
        if ($null -eq $hit -or $done.ContainsKey($hit.rel)) { continue }
        $done[$hit.rel] = $true
        $where = $hit.rel
        $records.Add([ordered]@{ path = $hit.rel; writers = [string[]]@(Get-PathWriters $hit.file.FullName) })
      } catch { $notes.Add(("{0}: права не прочитаны ({1})" -f $where, $_.Exception.Message)) }
    }
    foreach ($r in $records) { foreach ($sid in $r.writers) { Resolve-SidName $sid } }
    $acl = $records.ToArray()
  }
  return (& $result)
}

# Имена SID: собираются из ACE и самих объектов, чтобы анализатор не
# ходил в домен за именами.
$principals = @{}
# Значение для фильтра LDAP (RFC 4515): \, *, (, ) и NUL — шестнадцатеричными кодами.
function Format-LdapFilterValue([string]$value) {
  $chars = foreach ($c in $value.ToCharArray()) { if ("\*()`0".IndexOf($c) -ge 0) { '\{0:x2}' -f [int]$c } else { [string]$c } }
  -join $chars
}

function Register-Principal([string]$sid, [string]$name, [string]$class) {
  if (-not $sid) { return }
  if ($principals.ContainsKey($sid)) { return }
  $principals[$sid] = @{ name = $name; class = $class }
}
function Resolve-SidName([string]$sid) {
  if (-not $sid -or $principals.ContainsKey($sid)) { return }
  try {
    $nt = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    Register-Principal $sid $nt "unknown"
  } catch { }
}
function Register-AceSids($sd) {
  if ($null -eq $sd) { return }
  try {
    foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
      Resolve-SidName $rule.IdentityReference.Value
    }
  } catch { }
}

# Пункты меню → что собирать. Пункт 1 = 2,5,6,7; 3 и 4 сочетаются, 2 их исключает; 5–7 сочетаются
# между собой и с выгрузкой AD. Неверный ввод — исключение с текстом для пользователя.
function Resolve-Selection([string]$text) {
  $items = @(([string]$text).Trim() -split '[,\s]+' | Where-Object { $_ })
  if ($items.Count -eq 0) { throw "Ничего не выбрано: введите номера пунктов через запятую, например 5,7" }
  $set = @{}
  foreach ($item in $items) {
    if ($item -notmatch '^[1-7]$') { throw ("Нет пункта «{0}»: выберите номера от 1 до 7" -f $item) }
    $set[[int]$item] = $true
  }
  if ($set.ContainsKey(1)) { foreach ($n in 2, 5, 6, 7) { $set[$n] = $true } }
  if ($set.ContainsKey(2) -and ($set.ContainsKey(3) -or $set.ContainsKey(4))) {
    throw "Пункты 1 и 2 — полная выгрузка AD, с сокращениями 3 и 4 они не сочетаются"
  }
  $picked = @()
  if ($set.ContainsKey(5)) { $picked += "ca" }
  if ($set.ContainsKey(6)) { $picked += "dc" }
  if ($set.ContainsKey(7)) { $picked += "web" }
  return [pscustomobject]@{
    Ad = [bool]($set.ContainsKey(2) -or $set.ContainsKey(3) -or $set.ContainsKey(4))
    SkipComputerAcl = [bool]$set.ContainsKey(3)
    SkipSysvol = [bool]$set.ContainsKey(4)
    Sections = $picked
  }
}

function Show-Menu {
  Write-Host ""
  Write-Host "1  Всё: выгрузка AD и данные ЦС (два файла)"
  Write-Host "2  Выгрузка AD полностью"
  Write-Host "3  Выгрузка AD без ACL компьютеров (быстрее)"
  Write-Host "4  Выгрузка AD без SYSVOL"
  Write-Host "5  Данные ЦС: настройки и права центров сертификации"
  Write-Host "6  Контроллеры домена: реестр, службы, SMB"
  Write-Host "7  Данные ЦС: проверка веб-выдачи"
}

# -Sections ca,dc из powershell.exe -File приходит одной строкой «ca,dc» — делим сами.
function Resolve-Sections([string[]]$names) {
  $known = @("ca", "dc", "web")
  $want = @($names | ForEach-Object { ([string]$_) -split '[,\s]+' } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
  foreach ($n in $want) { if ($known -notcontains $n) { throw ("Неизвестный раздел «{0}»: допустимы ca, dc, web" -f $n) } }
  return ,@($known | Where-Object { $want -contains $_ })
}

# Контейнера может не быть (в лесу нет AD CS) — это не ошибка; отказ чтения — предупреждение,
# выгрузка остаётся без этих объектов.
function Get-AdOptional([string]$what, [hashtable]$query) {
  try { return @(Get-ADObject @ad @query -ErrorAction SilentlyContinue) }
  catch { Add-Warning ("{0}: {1}" -f $what, $_.Exception.Message); return @() }
}

# То же, но отказ отличим от пустого ответа: $null — раздел не прочитан (поле выгрузки тогда null).
function Read-AdSection([string]$what, [hashtable]$query) {
  try { return ,@(Get-ADObject @ad @query -ErrorAction SilentlyContinue) }
  catch { Add-Warning ("{0}: {1}" -f $what, $_.Exception.Message); return $null }
}

function Collect-Ad([bool]$noComputerAcl, [bool]$noSysvol) {
  Write-Step "Свойства домена"
  $domainObj = Get-ADObject @ad -Identity $domain.DistinguishedName -Properties "ms-DS-MachineAccountQuota", nTSecurityDescriptor, minPwdLength, lockoutThreshold, pwdProperties, pwdHistoryLength, gPLink, gPOptions
  # null у поля — «не прочитано»: отказ необязательного чтения ниже оставляет его null.
  $domainInfo = @{
    dns_root = $domain.DNSRoot
    dn = $domain.DistinguishedName
    netbios = $netbios
    sid = $domain.DomainSID.Value
    configuration_dn = $root.configurationNamingContext
    schema_dn = $root.schemaNamingContext
    machine_account_quota = AsInt $domainObj."ms-DS-MachineAccountQuota"
    functional_level = [string]$domain.DomainMode
    min_pwd_length = AsInt $domainObj.minPwdLength
    lockout_threshold = AsInt $domainObj.lockoutThreshold
    pwd_properties = AsInt $domainObj.pwdProperties
    pwd_history_length = AsInt $domainObj.pwdHistoryLength
    forest_functional_level = $null
    recycle_bin = $null
    ds_heuristics = $null
    smartcard_rotation = $null
    laps_legacy_schema = $null
    laps_schema = $null
    last_backup = $null
    backup_read = $null
    sysvol_replication = $null
    schema_poss_superiors = $null
  }

  Write-Step "GUID расширенных прав и атрибутов схемы"
  $extRights = @{}
  foreach ($name in @("DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set", "Enroll", "AutoEnroll")) {
    $o = Get-ADObject @ad -SearchBase ("CN=Extended-Rights," + $root.configurationNamingContext) -LDAPFilter "(displayName=$name)" -Properties rightsGuid -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($o -and $o.rightsGuid) { $extRights[$name] = [string]$o.rightsGuid }
  }
  $schemaAttrs = @{}
  $kc = Get-ADObject @ad -SearchBase $root.schemaNamingContext -LDAPFilter "(lDAPDisplayName=msDS-KeyCredentialLink)" -Properties schemaIDGUID -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($kc -and $kc.schemaIDGUID) { $schemaAttrs["msDS-KeyCredentialLink"] = ([Guid]::new([byte[]]$kc.schemaIDGUID)).ToString() }

  Write-Step "Настройки домена и леса"
  try { $domainInfo["forest_functional_level"] = [string](Get-ADForest @ad).ForestMode }
  catch { Add-Warning ("функциональный уровень леса не прочитан: {0}" -f $_.Exception.Message) }
  try { $domainInfo["recycle_bin"] = [bool](@((Get-ADOptionalFeature @ad -Identity "Recycle Bin Feature").EnabledScopes | Where-Object { $_ }).Count -gt 0) }
  catch { Add-Warning ("корзина AD не прочитана: {0}" -f $_.Exception.Message) }
  $dsh = Read-AdSection "dSHeuristics не прочитан" @{ SearchBase = "CN=Directory Service,CN=Windows NT,CN=Services," + $root.configurationNamingContext; SearchScope = "Base"; LDAPFilter = "(objectClass=*)"; Properties = @("dSHeuristics") }
  if ($null -ne $dsh -and $dsh.Count -gt 0) { $domainInfo["ds_heuristics"] = [string]$dsh[0].dSHeuristics }
  # Объекта DFSR нет — SYSVOL реплицирует FRS. Поиск от CN=System (он есть всегда), а не по самому
  # объекту: отсутствие базы поиска модуль может счесть ошибкой.
  $dfsrDn = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System," + $domain.DistinguishedName
  $dfsr = Read-AdSection "способ репликации SYSVOL не определён" @{ SearchBase = "CN=System," + $domain.DistinguishedName; LDAPFilter = "(cn=Domain System Volume)"; Properties = @("cn") }
  if ($null -ne $dfsr) { $domainInfo["sysvol_replication"] = $(if (@($dfsr | Where-Object { $_.DistinguishedName -eq $dfsrDn }).Count -gt 0) { "dfsr" } else { "ntfrs" }) }

  # Имена схемы, которых может не быть (LAPS, Server 2016, Exchange, dMSA): модуль отвергает запрос с
  # неизвестным свойством целиком, поэтому такие свойства запрашиваются только после этой проверки.
  $smartcardAttr = "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"
  $lapsExpiry = [ordered]@{ "ms-Mcs-AdmPwdExpirationTime" = "lapsExpiry"; "msLAPS-PasswordExpirationTime" = "lapsNewExpiry" }
  $optionalNames = @("ms-Mcs-AdmPwd", "msLAPS-Password", $smartcardAttr, "msExchStorageGroup", "msDS-DelegatedManagedServiceAccount") + @($lapsExpiry.Keys)
  $schemaFilter = "(|" + (($optionalNames | ForEach-Object { "(lDAPDisplayName=$_)" }) -join "") + ")"
  $schemaFound = Read-AdSection "схема не прочитана" @{ SearchBase = $root.schemaNamingContext; LDAPFilter = $schemaFilter; Properties = @("lDAPDisplayName", "schemaIDGUID", "possSuperiors", "systemPossSuperiors") }
  $inSchema = @{}
  foreach ($e in $schemaFound) { $inSchema[[string]$e.lDAPDisplayName] = $e }
  $lapsAttrs = @($lapsExpiry.Keys | Where-Object { $inSchema.ContainsKey($_) })
  # Ключ есть — схема проверена; пустое значение — класса нет. Схема не прочитана — ключа нет.
  $schemaClasses = @{}
  if ($null -ne $schemaFound) {
    $domainInfo["laps_legacy_schema"] = $inSchema.ContainsKey("ms-Mcs-AdmPwd")
    $domainInfo["laps_schema"] = $inSchema.ContainsKey("msLAPS-Password")
    $superiors = @{}
    $storage = $inSchema["msExchStorageGroup"]
    if ($storage) { $superiors["msExchStorageGroup"] = [string[]]@(@($storage.possSuperiors) + @($storage.systemPossSuperiors) | Where-Object { $_ }) }
    $domainInfo["schema_poss_superiors"] = $superiors
    $dmsa = $inSchema["msDS-DelegatedManagedServiceAccount"]
    $schemaClasses["msDS-DelegatedManagedServiceAccount"] = $(if ($dmsa -and $dmsa.schemaIDGUID) { ([Guid]::new([byte[]]$dmsa.schemaIDGUID)).ToString() } else { "" })
    # Атрибута нет в схеме (лес старше Server 2016) — ротация выключена.
    if (-not $inSchema.ContainsKey($smartcardAttr)) { $domainInfo["smartcard_rotation"] = $false }
  }
  # Метаданные репликации — конструируемый атрибут: отдаётся только по явному запросу.
  $metaProps = @("msDS-ReplAttributeMetaData")
  if ($inSchema.ContainsKey($smartcardAttr)) { $metaProps += $smartcardAttr }
  try {
    $meta = Get-ADObject @ad -Identity $domain.DistinguishedName -Properties $metaProps
    $values = [string[]]@($meta."msDS-ReplAttributeMetaData" | Where-Object { $_ })
    $domainInfo["last_backup"] = Get-LastBackup $values
    $domainInfo["backup_read"] = [bool]($values.Count -gt 0)
    if ($inSchema.ContainsKey($smartcardAttr)) { $domainInfo["smartcard_rotation"] = [bool]$meta.$smartcardAttr }
  } catch { Add-Warning ("метаданные репликации корня домена не прочитаны: {0}" -f $_.Exception.Message) }

  $objects = New-Object System.Collections.Generic.List[object]

  function Add-Account($o, [string]$class, [bool]$withSd) {
    $sid = SidString $o.objectSid
    $uac = AsInt $o.userAccountControl
    $rec = @{
      dn = $o.DistinguishedName
      class = $class
      sid = $sid
      sam = [string]$o.sAMAccountName
      name = [string]$o.Name
      uac = $uac
      lastLogonTimestamp = AsInt64 $o.lastLogonTimestamp
      pwdLastSet = AsInt64 $o.pwdLastSet
      spn = AsList $o.servicePrincipalName
      trustedForDelegation = [bool](($uac -band 0x80000) -ne 0)
      trustedToAuthForDelegation = [bool](($uac -band 0x1000000) -ne 0)
      allowedToDelegateTo = AsList $o."msDS-AllowedToDelegateTo"
      supportedEncryptionTypes = AsInt $o."msDS-SupportedEncryptionTypes"
      adminCount = AsInt $o.adminCount
      altSecurityIdentities = AsList $o.altSecurityIdentities
      primaryGroupID = AsInt $o.primaryGroupID
      sIDHistory = SidList $o.sIDHistory
      whenCreated = IsoTime $o.whenCreated
      scriptPath = $(if ($o.scriptPath) { [string]$o.scriptPath } else { $null })
    }
    if ($class -eq "user" -and $unixDns.Contains([string]$o.DistinguishedName)) { $rec["hasUnixPassword"] = $true }
    if ($class -eq "computer") {
      # Атрибуты LAPS запрошены, только если они есть в схеме ($lapsAttrs).
      foreach ($attr in $lapsExpiry.Keys) { $rec[$lapsExpiry[$attr]] = $(if ($lapsAttrs -contains $attr) { AsInt64 $o.$attr } else { $null }) }
      $rec["creatorSid"] = AnySid $o."ms-DS-CreatorSID"
      $rec["revealOnDemand"] = AsList $o."msDS-RevealOnDemandGroup"
      $rec["neverReveal"] = AsList $o."msDS-NeverRevealGroup"
      # Значение на каждый раскрытый секрет учётки — DN повторяются; порядок сохраняется.
      $revealed = New-Object System.Collections.Generic.List[string]
      $seen = New-Object 'System.Collections.Generic.HashSet[string]'
      foreach ($v in @($o."msDS-RevealedUsers" | Where-Object { $_ })) {
        $dn = Get-DnBinaryDn ([string]$v)
        if ($seen.Add($dn)) { $revealed.Add($dn) }
      }
      $rec["revealedUsers"] = $revealed.ToArray()
      $rec["krbTgtLink"] = AsStr $o."msDS-KrbTgtLink"
      $rec["allowedToActOnBehalf"] = ToBase64Sd $o."msDS-AllowedToActOnBehalfOfOtherIdentity"
      if ($o."msDS-AllowedToActOnBehalfOfOtherIdentity") { Register-AceSids $o."msDS-AllowedToActOnBehalfOfOtherIdentity" }
      if ($withSd) { $rec["sd"] = ToBase64Sd $o.nTSecurityDescriptor; Register-AceSids $o.nTSecurityDescriptor }
      $rec["dNSHostName"] = [string]$o.dNSHostName
      $rec["operatingSystem"] = [string]$o.operatingSystem
      $rec["operatingSystemVersion"] = [string]$o.operatingSystemVersion
    }
    if ($sid) { Register-Principal $sid ("{0}\{1}" -f $netbios, $o.sAMAccountName) $class }
    $objects.Add($rec) | Out-Null
  }

  Write-Step "Пользователи"
  $n0 = $objects.Count
  # Unix-пароли: только наличие — по фильтру с одним именем учётки; значения паролей не читаются.
  $unixDns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $unix = Read-AdSection "Unix-пароли не проверены" @{ LDAPFilter = "(&(objectCategory=person)(objectClass=user)(|(userPassword=*)(unixUserPassword=*)))"; Properties = @("sAMAccountName") }
  foreach ($u in $unix) { [void]$unixDns.Add([string]$u.DistinguishedName) }
  $userProps = @("sAMAccountName","Name","objectSid","userAccountControl","lastLogonTimestamp","pwdLastSet","servicePrincipalName","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","adminCount","altSecurityIdentities","primaryGroupID","sIDHistory","whenCreated","scriptPath")
  Get-ADObject @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -Properties $userProps | ForEach-Object { Add-Account $_ "user" $false }
  Write-Step ("  пользователей: {0}, с Unix-паролем: {1}" -f ($objects.Count - $n0), $unixDns.Count)

  Write-Step "Компьютеры"
  $n0 = $objects.Count
  $compProps = $userProps + @("msDS-AllowedToActOnBehalfOfOtherIdentity", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "ms-DS-CreatorSID", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedUsers", "msDS-KrbTgtLink") + $lapsAttrs
  if (-not $noComputerAcl) { $compProps += "nTSecurityDescriptor" }
  Get-ADObject @ad -LDAPFilter "(objectClass=computer)" -Properties $compProps | ForEach-Object { Add-Account $_ "computer" (-not $noComputerAcl) }
  Write-Step ("  компьютеров: {0}" -f ($objects.Count - $n0))

  Write-Step "Группы"
  $n0 = $objects.Count
  Get-ADObject @ad -LDAPFilter "(objectClass=group)" -Properties sAMAccountName,Name,objectSid,member,adminCount | ForEach-Object {
    $sid = SidString $_.objectSid
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "group"; sid = $sid; sam = [string]$_.sAMAccountName; name = [string]$_.Name
      member = AsList $_.member; adminCount = AsInt $_.adminCount
    }) | Out-Null
    if ($sid) { Register-Principal $sid ("{0}\{1}" -f $netbios, $_.sAMAccountName) "group" }
  }
  Write-Step ("  групп: {0}" -f ($objects.Count - $n0))

  # Дескрипторы критичных групп, их рекурсивных участников (правило LDAP_MATCHING_RULE_IN_CHAIN) и учёток
  # RID 500 и 502 — в поле sd уже собранных записей пользователей и групп.
  Write-Step "Права на критичные объекты"
  $byDn = @{}
  $bySid = @{}
  foreach ($r in $objects) {
    if ($r["class"] -eq "user" -or $r["class"] -eq "group") {
      $byDn[([string]$r["dn"]).ToLowerInvariant()] = $r
      if ($r["sid"]) { $bySid[$r["sid"]] = $r }
    }
  }
  $domSid = $domain.DomainSID.Value
  $critical = [ordered]@{}
  $wanted = @($CriticalGroupRids | ForEach-Object { "$domSid-$_" }) + @($CriticalBuiltinRids | ForEach-Object { "S-1-5-32-$_" })
  foreach ($s in $wanted) { if ($bySid.ContainsKey($s)) { $critical[([string]$bySid[$s]["dn"]).ToLowerInvariant()] = $bySid[$s] } }
  foreach ($r in $byDn.Values) { if ($r["class"] -eq "group" -and $CriticalGroupNames -contains $r["sam"]) { $critical[([string]$r["dn"]).ToLowerInvariant()] = $r } }
  $script:criticalSd = 0
  function Set-CriticalSd($o) {
    $rec = $byDn[([string]$o.DistinguishedName).ToLowerInvariant()]
    if ($rec -and $o.nTSecurityDescriptor) {
      $rec["sd"] = ToBase64Sd $o.nTSecurityDescriptor
      Register-AceSids $o.nTSecurityDescriptor
      $script:criticalSd++
    }
  }
  $own = @($critical.Values) + @(foreach ($rid in 500, 502) { if ($bySid.ContainsKey("$domSid-$rid")) { $bySid["$domSid-$rid"] } })
  foreach ($r in $own) {
    try { Set-CriticalSd (Get-ADObject @ad -Identity $r["dn"] -Properties nTSecurityDescriptor) }
    catch { Add-Warning ("дескрипторы критичных объектов не прочитаны ({0}): {1}" -f $r["dn"], $_.Exception.Message) }
  }
  foreach ($g in $critical.Values) {
    $flt = "(memberOf:1.2.840.113556.1.4.1941:={0})" -f (Format-LdapFilterValue $g["dn"])
    try {
      $members = @(Get-ADObject @ad -LDAPFilter $flt -Properties nTSecurityDescriptor -ResultSetSize ($CriticalMembersLimit + 1))
      if ($members.Count -gt $CriticalMembersLimit) {
        Add-Warning ("дескрипторы критичных объектов не прочитаны у части участников {0}: их больше {1}" -f $g["sam"], $CriticalMembersLimit)
        $members = $members[0..($CriticalMembersLimit - 1)]
      }
      foreach ($m in $members) { Set-CriticalSd $m }
    } catch { Add-Warning ("дескрипторы критичных объектов не прочитаны (участники {0}): {1}" -f $g["sam"], $_.Exception.Message) }
  }
  Write-Step ("  групп: {0}, дескрипторов: {1}" -f $critical.Count, $script:criticalSd)

  Write-Step "Корень домена, AdminSDHolder, OU"
  # Привязка GPO: gPLink без атрибута — пустая строка (сборщик ссылки читал, их нет; null — старый сборщик).
  $objects.Add(@{ dn = $domain.DistinguishedName; class = "domainDNS"; sid = $domain.DomainSID.Value; sd = ToBase64Sd $domainObj.nTSecurityDescriptor
    gpLink = [string]$domainObj.gPLink; gpOptions = AsInt $domainObj.gPOptions }) | Out-Null
  Register-AceSids $domainObj.nTSecurityDescriptor
  $holder = Get-ADObject @ad -Identity ("CN=AdminSDHolder,CN=System," + $domain.DistinguishedName) -Properties nTSecurityDescriptor
  $objects.Add(@{ dn = $holder.DistinguishedName; class = "container"; sd = ToBase64Sd $holder.nTSecurityDescriptor }) | Out-Null
  Register-AceSids $holder.nTSecurityDescriptor
  Get-ADObject @ad -LDAPFilter "(objectClass=organizationalUnit)" -Properties nTSecurityDescriptor, gPLink, gPOptions | ForEach-Object {
    $objects.Add(@{ dn = $_.DistinguishedName; class = "organizationalUnit"; sd = ToBase64Sd $_.nTSecurityDescriptor; gpLink = [string]$_.gPLink; gpOptions = AsInt $_.gPOptions }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
  }

  Write-Step "Групповые политики"
  $sysvol = @{}
  # Блок gpo: DN GPO → файлы из SYSVOL. С -SkipSysvol его в выгрузке нет, причина в notes.
  $gpo = @{}
  Get-ADObject @ad -SearchBase ("CN=Policies,CN=System," + $domain.DistinguishedName) -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName,gPCFileSysPath,flags,nTSecurityDescriptor | ForEach-Object {
    $objects.Add(@{ dn = $_.DistinguishedName; class = "groupPolicyContainer"; displayName = [string]$_.displayName; gpcFileSysPath = [string]$_.gPCFileSysPath; flags = AsInt $_.flags; sd = ToBase64Sd $_.nTSecurityDescriptor }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
    if (-not $noSysvol -and $_.gPCFileSysPath) {
      $files = Read-GpoFiles ([string]$_.gPCFileSysPath)
      if ($null -ne $files.tmpl) { $sysvol[$_.DistinguishedName] = @{ "GptTmpl.inf" = $files.tmpl } }
      $gpo[$_.DistinguishedName] = $files.data
    }
  }
  Write-Step ("  GPO с GptTmpl.inf: {0}, с файлами SYSVOL: {1}, с отказами чтения: {2}" -f $sysvol.Count, $gpo.Count, @($gpo.Values | Where-Object { $_.notes.Count -gt 0 }).Count)

  Write-Step "Шаблоны сертификатов"
  $n0 = $objects.Count
  $tplBase = "CN=Certificate Templates," + $pki
  Get-ADObject @ad -SearchBase $tplBase -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties cn,displayName,pKIExtendedKeyUsage,"msPKI-Enrollment-Flag","msPKI-Certificate-Name-Flag","msPKI-RA-Signature","msPKI-Template-Schema-Version","msPKI-Certificate-Policy","msPKI-Certificate-Application-Policy","msPKI-RA-Application-Policies","msPKI-Cert-Template-OID",nTSecurityDescriptor -ErrorAction SilentlyContinue | ForEach-Object {
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "pKICertificateTemplate"; cn = [string]$_.cn; displayName = [string]$_.displayName
      pKIExtendedKeyUsage = AsList $_.pKIExtendedKeyUsage
      "msPKI-Enrollment-Flag" = AsInt $_."msPKI-Enrollment-Flag"
      "msPKI-Certificate-Name-Flag" = AsInt $_."msPKI-Certificate-Name-Flag"
      "msPKI-RA-Signature" = AsInt $_."msPKI-RA-Signature"
      "msPKI-Template-Schema-Version" = AsInt $_."msPKI-Template-Schema-Version"
      "msPKI-Certificate-Policy" = AsList $_."msPKI-Certificate-Policy"
      "msPKI-Certificate-Application-Policy" = AsList $_."msPKI-Certificate-Application-Policy"
      "msPKI-RA-Application-Policies" = AsList $_."msPKI-RA-Application-Policies"
      "msPKI-Cert-Template-OID" = AsStr $_."msPKI-Cert-Template-OID"
      sd = ToBase64Sd $_.nTSecurityDescriptor
    }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
  }
  Write-Step ("  шаблонов: {0}" -f ($objects.Count - $n0))

  Write-Step "Центры сертификации и контейнеры PKI"
  $n0 = $objects.Count
  Get-AdOptional "центры сертификации" @{ SearchBase = "CN=Enrollment Services," + $pki; LDAPFilter = "(objectClass=pKIEnrollmentService)"; Properties = @("cn", "dNSHostName", "certificateTemplates", "msPKI-Enrollment-Servers", "nTSecurityDescriptor") } | ForEach-Object {
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "pKIEnrollmentService"; cn = [string]$_.cn; dNSHostName = [string]$_.dNSHostName
      certificateTemplates = AsList $_.certificateTemplates
      "msPKI-Enrollment-Servers" = AsList $_."msPKI-Enrollment-Servers"
      sd = ToBase64Sd $_.nTSecurityDescriptor
    }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
  }
  Write-Step ("  центров сертификации: {0}" -f ($objects.Count - $n0))
  $n0 = $objects.Count
  foreach ($scope in @("Base", "OneLevel")) {
    Get-AdOptional "контейнеры PKI" @{ SearchBase = $pki; SearchScope = $scope; LDAPFilter = "(objectClass=*)"; Properties = @("nTSecurityDescriptor") } | ForEach-Object {
      $objects.Add(@{ dn = $_.DistinguishedName; class = "pkiContainer"; sd = ToBase64Sd $_.nTSecurityDescriptor }) | Out-Null
      Register-AceSids $_.nTSecurityDescriptor
    }
  }
  Write-Step ("  контейнеров PKI: {0}" -f ($objects.Count - $n0))
  # На один уровень: сам CN=OID тоже класса msPKI-Enterprise-Oid и уже записан как pkiContainer.
  $n0 = $objects.Count
  Get-AdOptional "политики выдачи (CN=OID)" @{ SearchBase = "CN=OID," + $pki; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=msPKI-Enterprise-Oid)"; Properties = @("displayName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink") } | ForEach-Object {
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "msPKI-Enterprise-Oid"; displayName = [string]$_.displayName
      "msPKI-Cert-Template-OID" = AsStr $_."msPKI-Cert-Template-OID"
      "msDS-OIDToGroupLink" = AsStr $_."msDS-OIDToGroupLink"
    }) | Out-Null
  }
  Write-Step ("  политик выдачи: {0}" -f ($objects.Count - $n0))

  Write-Step "Доверенные домены"
  $n0 = $objects.Count
  Get-AdOptional "доверенные домены" @{ SearchBase = "CN=System," + $domain.DistinguishedName; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=trustedDomain)"; Properties = @("flatName", "securityIdentifier", "trustAttributes", "trustDirection", "trustType", "trustPartner", "whenChanged", "msDS-SupportedEncryptionTypes") } | ForEach-Object {
    $trustSid = $null
    if ($_.securityIdentifier) {
      try { $trustSid = SidFromBytes ([byte[]]$_.securityIdentifier) } catch { }
    }
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "trustedDomain"; flatName = [string]$_.flatName; sid = $trustSid
      trustAttributes = AsInt $_.trustAttributes
      trustDirection = AsInt $_.trustDirection; trustType = AsInt $_.trustType; trustPartner = AsStr $_.trustPartner
      whenChanged = IsoTime $_.whenChanged; supportedEncryptionTypes = AsInt $_."msDS-SupportedEncryptionTypes"
    }) | Out-Null
  }
  Write-Step ("  доверенных доменов: {0}" -f ($objects.Count - $n0))

  Write-Step "Политики паролей (PSO)"
  $n0 = $objects.Count
  $psos = Read-AdSection "PSO не прочитаны" @{ SearchBase = "CN=Password Settings Container,CN=System," + $domain.DistinguishedName; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=msDS-PasswordSettings)"; Properties = @("msDS-MinimumPasswordLength", "msDS-LockoutThreshold", "msDS-PasswordReversibleEncryptionEnabled", "msDS-PasswordComplexityEnabled", "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo") }
  # Контейнер PSO по умолчанию читают только администраторы: пусто без ошибки — «не видно», а не «нет».
  if ($null -ne $psos -and $psos.Count -eq 0) { Add-Warning "PSO не найдены: при сборе не администратором домена они не видны" }
  foreach ($p in $psos) {
    $objects.Add(@{
      dn = $p.DistinguishedName; class = "msDS-PasswordSettings"; name = [string]$p.Name
      psoMinLength = AsInt $p."msDS-MinimumPasswordLength"; psoLockoutThreshold = AsInt $p."msDS-LockoutThreshold"
      psoReversible = AsBool $p."msDS-PasswordReversibleEncryptionEnabled"; psoComplexity = AsBool $p."msDS-PasswordComplexityEnabled"
      psoPrecedence = AsInt $p."msDS-PasswordSettingsPrecedence"; psoAppliesTo = AsList $p."msDS-PSOAppliesTo"
    }) | Out-Null
  }
  Write-Step ("  PSO: {0}" -f ($objects.Count - $n0))

  Write-Step "Зоны DNS"
  $n0 = $objects.Count
  $forestDn = [string]$root.rootDomainNamingContext
  # Зоны в System лежат в CN=MicrosoftDNS,CN=System; поиск от CN=System — его отсутствие не ошибка.
  $zoneBases = [ordered]@{
    DomainDnsZones = "DC=DomainDnsZones," + $domain.DistinguishedName
    ForestDnsZones = "DC=ForestDnsZones," + $forestDn
    System = "CN=System," + $domain.DistinguishedName
  }
  # Разделов DomainDnsZones и ForestDnsZones может не быть (DNS не интегрирован с AD) — это не отказ: есть ли
  # раздел, видно по crossRef в CN=Partitions. Список разделов не прочитан — читаются все базы, как раньше.
  $partitions = $null
  try { $partitions = @(Get-ADObject @ad -SearchBase ("CN=Partitions," + $root.configurationNamingContext) -SearchScope OneLevel -LDAPFilter "(objectClass=crossRef)" -Properties nCName) } catch { }
  $namingContexts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  if ($null -ne $partitions) { foreach ($p in $partitions) { if ($p.nCName) { [void]$namingContexts.Add([string]$p.nCName) } } }
  # crossRef своего домена есть всегда: без него список неполон (не виден) и считается непрочитанным.
  if (-not $namingContexts.Contains($domain.DistinguishedName)) { $partitions = $null }
  foreach ($partition in $zoneBases.Keys) {
    if ($partition -ne "System" -and $null -ne $partitions -and -not $namingContexts.Contains($zoneBases[$partition])) { continue }
    $zones = Read-AdSection ("зоны DNS не прочитаны ({0})" -f $partition) @{ SearchBase = $zoneBases[$partition]; LDAPFilter = "(objectClass=dnsZone)"; Properties = @("dNSProperty", "nTSecurityDescriptor") }
    foreach ($z in $zones) {
      $objects.Add(@{
        dn = $z.DistinguishedName; class = "dnsZone"; name = [string]$z.Name; partition = $partition
        allowUpdate = Get-DnsAllowUpdate ([byte[][]]@($z.dNSProperty | Where-Object { $null -ne $_ }))
        sd = ToBase64Sd $z.nTSecurityDescriptor
      }) | Out-Null
      Register-AceSids $z.nTSecurityDescriptor
    }
  }
  Write-Step ("  зон DNS: {0}" -f ($objects.Count - $n0))

  Write-Step "Сайты и подсети"
  $n0 = $objects.Count
  $sites = Read-AdSection "сайты не прочитаны" @{ SearchBase = "CN=Sites," + $root.configurationNamingContext; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=site)"; Properties = @("name", "gPLink", "gPOptions") }
  foreach ($s in $sites) { $objects.Add(@{ dn = $s.DistinguishedName; class = "site"; name = [string]$s.Name; gpLink = [string]$s.gPLink; gpOptions = AsInt $s.gPOptions }) | Out-Null }
  $subnets = Read-AdSection "подсети не прочитаны" @{ SearchBase = "CN=Subnets,CN=Sites," + $root.configurationNamingContext; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=subnet)"; Properties = @("siteObject") }
  foreach ($s in $subnets) { $objects.Add(@{ dn = $s.DistinguishedName; class = "subnet"; name = [string]$s.Name; site = $(if ($s.siteObject) { [string]$s.siteObject } else { $null }) }) | Out-Null }
  Write-Step ("  сайтов и подсетей: {0}" -f ($objects.Count - $n0))

  # Что не прочитано: анализатор показывает это в «не проверено». Отказ по центрам сертификации
  # мог прийти дважды (план и выгрузка) — повторы убираются.
  $notes = @()
  if ($noSysvol) { $notes += "чтение SYSVOL выключено (-SkipSysvol)" }
  $notes += @($script:warnings | Select-Object -Unique)

  $export = @{
    format = $FormatVersion
    collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    collector = @{ kind = "powershell"; version = $CollectorVersion; host = $env:COMPUTERNAME; account = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME); notes = [string[]]$notes; critical_acl = $true }
    domain = $domainInfo
    guids = @{ extended_rights = $extRights; schema_attributes = $schemaAttrs; schema_classes = $schemaClasses }
    objects = $objects.ToArray()
    sysvol = $sysvol
    principals = $principals
  }
  if (-not $noSysvol) { $export["gpo"] = $gpo }
  return $export
}

# Центры сертификации домена: имя (cn), сервер и адреса служб веб-выдачи.
function Get-CaList {
  $list = New-Object System.Collections.Generic.List[object]
  Get-AdOptional "центры сертификации" @{ SearchBase = "CN=Enrollment Services," + $pki; LDAPFilter = "(objectClass=pKIEnrollmentService)"; Properties = @("cn", "dNSHostName", "msPKI-Enrollment-Servers") } | ForEach-Object {
    $list.Add([pscustomobject]@{ Name = [string]$_.cn; DnsName = [string]$_.dNSHostName; EnrollmentServers = AsList $_."msPKI-Enrollment-Servers" })
  }
  return ,$list.ToArray()
}

# Адреса веб-выдачи: /certsrv/ по http и https на каждом ЦС и адреса служб из msPKI-Enrollment-Servers
# (значение — «приоритет, способ входа, флаг и URL» через перевод строки).
function Get-WebUrls($cas) {
  $urls = New-Object System.Collections.Generic.List[string]
  $seen = @{}
  foreach ($ca in $cas) {
    $found = @()
    if ($ca.DnsName) { $found += "http://{0}/certsrv/" -f $ca.DnsName; $found += "https://{0}/certsrv/" -f $ca.DnsName }
    foreach ($v in $ca.EnrollmentServers) { foreach ($m in [regex]::Matches([string]$v, 'https?://\S+')) { $found += $m.Value } }
    foreach ($u in $found) { if (-not $seen.ContainsKey($u)) { $seen[$u] = $true; $urls.Add($u) } }
  }
  return ,$urls.ToArray()
}

# Значения одного раздела удалённого реестра (HKLM). Раздела нет — $null; значения нет — $null в нём.
function Read-RemoteRegistry([string]$computer, [string]$path, [string[]]$names) {
  $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computer)
  try {
    $key = $base.OpenSubKey($path)
    if ($null -eq $key) { return $null }
    try {
      $values = @{}
      foreach ($n in $names) { $values[$n] = $key.GetValue($n) }
      return $values
    } finally { $key.Close() }
  } finally { $base.Close() }
}

# Вывод certutil -getreg строками; значения нет в реестре — пустой список; прочий отказ — исключение.
function Invoke-CertutilGetReg([string]$config, [string]$name) {
  if (-not (Get-Command certutil.exe -ErrorAction SilentlyContinue)) { throw "certutil.exe не найден" }
  # certutil пишет и в stderr; при Stop Windows PowerShell 5.1 превратил бы первую такую строку в исключение.
  $ErrorActionPreference = "Continue"
  $lines = @(& certutil.exe -config $config -getreg $name 2>&1 | ForEach-Object { [string]$_ })
  $code = $LASTEXITCODE
  if ($code -eq 0) { return ,$lines }
  if (($lines -join " ") -match '0x80070002') { return ,@() }
  $last = @($lines | Where-Object { $_.Trim() }) | Select-Object -Last 1
  throw ("certutil -getreg {0}: код {1}: {2}" -f $name, $code, $last)
}

# «EditFlags REG_DWORD = 11014e (1114446)» → 1114446. Берётся шестнадцатеричная часть: десятичная
# у значений со старшим битом печатается со знаком.
function Read-CertutilDword([string[]]$lines) {
  foreach ($line in @($lines)) {
    if ($line -match 'REG_DWORD\s*=\s*([0-9a-fA-F]+)') { return [Convert]::ToInt64($Matches[1], 16) }
  }
  return $null
}

# «DisableExtensionList REG_MULTI_SZ =» и строки «0: 1.3.6…» → список; REG_SZ — одно значение.
function Read-CertutilList([string[]]$lines) {
  $out = New-Object System.Collections.Generic.List[string]
  $multi = $false
  foreach ($line in @($lines)) {
    if ($null -eq $line) { continue }
    if ($line -match 'REG_MULTI_SZ\s*=') { $multi = $true; continue }
    if ($line -match 'REG_(?:EXPAND_)?SZ\s*=\s*(.*)$') { if ($Matches[1].Trim()) { $out.Add($Matches[1].Trim()) }; continue }
    if ($multi -and $line -match '^\s*\d+:\s*(\S.*)$') { $out.Add($Matches[1].Trim()) }
  }
  return ,$out.ToArray()
}

function Get-CaSettings($ca) {
  $rec = [ordered]@{
    name = $ca.Name; host = $ca.DnsName; os_build = ""
    edit_flags = $null; interface_flags = $null; disable_extension_list = [string[]]@(); security = $null; error = ""
  }
  if (-not $ca.DnsName) { $rec.error = "у центра сертификации не задан dNSHostName"; return $rec }
  $errs = New-Object System.Collections.Generic.List[string]
  try {
    $computer = Get-ADComputer @ad -Filter ("DNSHostName -eq '{0}'" -f $ca.DnsName) -Properties OperatingSystemVersion | Select-Object -First 1
    if ($computer -and $computer.OperatingSystemVersion) { $rec.os_build = [string]$computer.OperatingSystemVersion }
  } catch { $errs.Add("сборка ОС: " + (ErrorText $_)) }

  $config = "{0}\{1}" -f $ca.DnsName, $ca.Name
  $regPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\" + $ca.Name
  try {
    $rec.edit_flags = Read-CertutilDword (Invoke-CertutilGetReg $config "policy\EditFlags")
    $rec.disable_extension_list = [string[]](Read-CertutilList (Invoke-CertutilGetReg $config "policy\DisableExtensionList"))
    $rec.interface_flags = Read-CertutilDword (Invoke-CertutilGetReg $config "CA\InterfaceFlags")
  } catch {
    $certutilError = ErrorText $_
    try {
      $caKey = Read-RemoteRegistry $ca.DnsName $regPath @("InterfaceFlags")
      if ($null -eq $caKey) { throw ("раздела HKLM\{0} нет" -f $regPath) }
      $rec.interface_flags = AsDword $caKey.InterfaceFlags
      $policy = Read-RemoteRegistry $ca.DnsName ($regPath + "\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy") @("EditFlags", "DisableExtensionList")
      if ($policy) {
        $rec.edit_flags = AsDword $policy.EditFlags
        $rec.disable_extension_list = [string[]]@($policy.DisableExtensionList | Where-Object { $_ })
      }
    } catch { $errs.Add(("certutil: {0}; реестр: {1}" -f $certutilError, (ErrorText $_))) }
  }
  # Права ЦС certutil печатает текстом, а анализатору нужен сам дескриптор — он берётся из реестра.
  try {
    $sec = Read-RemoteRegistry $ca.DnsName $regPath @("Security")
    if ($null -eq $sec) { throw ("раздела HKLM\{0} нет" -f $regPath) }
    if ($sec.Security -is [byte[]]) { $rec.security = [Convert]::ToBase64String($sec.Security) }
    else { $errs.Add("Security: значения нет в реестре") }
  } catch { $errs.Add("Security: " + (ErrorText $_)) }
  $rec.error = $errs -join "; "
  return $rec
}

# Служба из Win32_Service → состояние для анализа; службы нет — absent. Запуск отключён, а служба ещё
# работает (до перезагрузки) — running: опасна работающая служба.
function ConvertTo-ServiceState($service) {
  if ($null -eq $service) { return "absent" }
  if ($service.State -eq "Running") { return "running" }
  if ($service.StartMode -eq "Disabled") { return "disabled" }
  return "stopped"
}

# Состояние контроллера: удалённый реестр (привязка сертификатов, NTLM, подпись LDAP, протоколы SCHANNEL,
# сборка ОС) и CIM (SMB, службы, время загрузки). registry_read и cim_read — отработал ли канал: при
# прочитанном реестре $null значит «значения нет», при непрочитанном — «не известно». Отказы — в error.
function Get-DcState([string]$dc) {
  $rec = [ordered]@{
    host = $dc; strong_binding = $null; mapping_methods = $null
    lm_compatibility = $null; no_lm_hash = $null; ldap_integrity = $null; ldap_channel_binding = $null; tls = $null
    smb1 = $null; smb_require_signing = $null; spooler = $null; webclient = $null; last_boot = $null; os_build = $null
    registry_read = $false; cim_read = $false; error = ""
  }
  $errs = New-Object System.Collections.Generic.List[string]
  try {
    $kdc = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Services\Kdc" @("StrongCertificateBindingEnforcement")
    if ($kdc) { $rec.strong_binding = AsDword $kdc.StrongCertificateBindingEnforcement }
    $schannel = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" @("CertificateMappingMethods")
    if ($schannel) { $rec.mapping_methods = AsDword $schannel.CertificateMappingMethods }
    $lsa = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Control\Lsa" @("LmCompatibilityLevel", "NoLMHash")
    if ($lsa) { $rec.lm_compatibility = AsDword $lsa.LmCompatibilityLevel; $rec.no_lm_hash = AsDword $lsa.NoLMHash }
    $ntds = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" @("LDAPServerIntegrity", "LdapEnforceChannelBinding")
    if ($ntds) { $rec.ldap_integrity = AsDword $ntds.LDAPServerIntegrity; $rec.ldap_channel_binding = AsDword $ntds.LdapEnforceChannelBinding }
    $tls = [ordered]@{}
    foreach ($protocol in @("SSL 3.0", "TLS 1.0", "TLS 1.1")) {
      $server = Read-RemoteRegistry $dc ("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Server" -f $protocol) @("Enabled")
      $tls[$protocol] = $(if ($server) { AsDword $server.Enabled } else { $null })
    }
    $rec.tls = $tls
    $version = Read-RemoteRegistry $dc "SOFTWARE\Microsoft\Windows NT\CurrentVersion" @("CurrentBuildNumber", "UBR")
    if ($version -and $version.CurrentBuildNumber) {
      $rec.os_build = [string]$version.CurrentBuildNumber
      if ($null -ne $version.UBR) { $rec.os_build += "." + (AsDword $version.UBR) }
    }
    $rec.registry_read = $true
  } catch { $errs.Add("реестр: " + (ErrorText $_)) }

  $session = $null
  try {
    try { $session = New-CimSession -ComputerName $dc -OperationTimeoutSec 30 }
    catch {
      $wsman = ErrorText $_
      try { $session = New-CimSession -ComputerName $dc -OperationTimeoutSec 30 -SessionOption (New-CimSessionOption -Protocol Dcom) }
      catch { throw ("WSMan: {0}; DCOM: {1}" -f $wsman, (ErrorText $_)) }
    }
    $rec.cim_read = $true
    try {
      $smb = Get-CimInstance -CimSession $session -Namespace root/Microsoft/Windows/SMB -ClassName MSFT_SmbServerConfiguration
      if ($null -eq $smb) { throw "MSFT_SmbServerConfiguration не вернул данных" }
      $rec.smb1 = AsBool $smb.EnableSMB1Protocol
      $rec.smb_require_signing = AsBool $smb.RequireSecuritySignature
    } catch { $errs.Add("SMB: " + (ErrorText $_)) }
    try {
      $services = @(Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='Spooler' OR Name='WebClient'")
      $rec.spooler = ConvertTo-ServiceState ($services | Where-Object { $_.Name -eq "Spooler" } | Select-Object -First 1)
      $rec.webclient = ConvertTo-ServiceState ($services | Where-Object { $_.Name -eq "WebClient" } | Select-Object -First 1)
    } catch { $errs.Add("службы: " + (ErrorText $_)) }
    try {
      $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
      $rec.last_boot = IsoTime $os.LastBootUpTime
    } catch { $errs.Add("время загрузки: " + (ErrorText $_)) }
  } catch { $errs.Add("CIM: " + (ErrorText $_)) }
  finally { if ($null -ne $session) { try { Remove-CimSession -CimSession $session } catch { } } }
  $rec.error = $errs -join "; "
  return $rec
}

# Значение для строки хода работы: нет значения — «—», флаг — да/нет.
function Format-DcValue($value) {
  if ($null -eq $value) { return "—" }
  if ($value -is [bool]) { return $(if ($value) { "да" } else { "нет" }) }
  return [string]$value
}

# Схемы из значений WWW-Authenticate: первое слово каждого вызова. .NET может склеить несколько
# заголовков через запятую, поэтому значение делится по запятым вне кавычек, а параметры
# (realm="…", charset=…) отбрасываются.
function Get-AuthSchemes([string[]]$headerValues) {
  $schemes = New-Object System.Collections.Generic.List[string]
  foreach ($value in @($headerValues)) {
    if (-not $value) { continue }
    $plain = [string]$value -replace '"(?:[^"\\]|\\.)*"', '""'
    foreach ($part in ($plain -split ',')) {
      $word = @($part.Trim() -split '\s+')[0]
      if ($word -match '^[A-Za-z][A-Za-z0-9._~+-]*$' -and $schemes -notcontains $word) { $schemes.Add($word) }
    }
  }
  return ,$schemes.ToArray()
}

# Запрос без учётных данных и без перенаправлений; код ответа и схемы входа. Ответы 4xx/5xx
# HttpWebRequest бросает исключением — код берётся из ответа внутри него.
function Test-WebEnrollment([string]$url) {
  $rec = [ordered]@{ url = $url; status = $null; auth = [string[]]@(); error = "" }
  $resp = $null
  try {
    $req = [System.Net.WebRequest]::Create($url)
    $req.Method = "GET"
    $req.UseDefaultCredentials = $false
    $req.Credentials = $null
    $req.AllowAutoRedirect = $false
    $req.Timeout = 10000
    $req.ReadWriteTimeout = 10000
    try { $resp = $req.GetResponse() }
    catch {
      $ex = $_.Exception
      while ($null -ne $ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
      if ($null -eq $ex -or $null -eq $ex.Response) { throw }
      $resp = $ex.Response
    }
    $rec.status = [int]$resp.StatusCode
    $rec.auth = [string[]](Get-AuthSchemes $resp.Headers.GetValues("WWW-Authenticate"))
  } catch {
    $rec.error = ErrorText $_
  } finally {
    if ($null -ne $resp) { $resp.Close() }
  }
  return $rec
}

function Collect-Ca([string[]]$sections, $cas, [string[]]$dcs, [string[]]$urls) {
  $caRecs = New-Object System.Collections.Generic.List[object]
  $dcRecs = New-Object System.Collections.Generic.List[object]
  $webRecs = New-Object System.Collections.Generic.List[object]
  if ($sections -contains "ca") {
    Write-Step "Настройки и права центров сертификации"
    foreach ($ca in $cas) {
      $r = Get-CaSettings $ca
      $caRecs.Add($r)
      if ($r.error) { Add-Warning ("ЦС {0}: {1}" -f $r.name, $r.error) }
      else { Write-Step ("  {0}: прочитан" -f $r.name) }
    }
  }
  if ($sections -contains "dc") {
    Write-Step "Состояние контроллеров домена"
    foreach ($dc in $dcs) {
      $r = Get-DcState $dc
      $dcRecs.Add($r)
      Write-Step ("  {0}: привязка {1}, NTLM {2}, подпись LDAP {3}, SMB1 {4}" -f $dc, (Format-DcValue $r.strong_binding),
        (Format-DcValue $r.lm_compatibility), (Format-DcValue $r.ldap_integrity), (Format-DcValue $r.smb1))
      if ($r.error) { Add-Warning ("контроллер {0}: {1}" -f $dc, $r.error) }
    }
  }
  if ($sections -contains "web") {
    Write-Step "Веб-выдача"
    # Windows PowerShell 5.1 по умолчанию может не предлагать TLS 1.2 — https-адреса тогда «недоступны».
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    foreach ($url in $urls) {
      $r = Test-WebEnrollment $url
      $webRecs.Add($r)
      if ($r.error) { Write-Step ("  {0}: нет ответа ({1})" -f $url, $r.error) }
      else { Write-Step (("  {0}: {1} {2}" -f $url, $r.status, ($r.auth -join ", ")).TrimEnd()) }
    }
  }
  return [ordered]@{
    format = $CaFormatVersion
    collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    collector = [ordered]@{ kind = "powershell"; version = $CollectorVersion; host = $env:COMPUTERNAME; account = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
    domain = [ordered]@{ sid = $domain.DomainSID.Value; dns_root = $domain.DNSRoot }
    sections = [string[]]@($sections)
    cas = $caRecs.ToArray()
    dcs = $dcRecs.ToArray()
    web = $webRecs.ToArray()
  }
}

function Write-GzipJson($data, [string]$path) {
  Write-Step "Запись $path"
  $json = $data | ConvertTo-Json -Depth 8 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $out = [System.IO.File]::Create($path)
  try {
    $gz = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Dispose()
  } finally { $out.Dispose() }
}

Write-Host "STools AD Collector $CollectorVersion (форматы $FormatVersion, $CaFormatVersion)" -ForegroundColor Green
$written = New-Object System.Collections.Generic.List[string]
# Без -Mode команды сборщика 1.x (-SkipSysvol -OutputPath …) и команды с -Sections работают без
# вопросов; меню — только когда кроме -Server и -Yes ничего не указано.
if (-not $PSBoundParameters.ContainsKey("Mode")) {
  $adSwitch = $PSBoundParameters.ContainsKey("SkipComputerAcl") -or $PSBoundParameters.ContainsKey("SkipSysvol")
  if ($PSBoundParameters.ContainsKey("Sections")) { $Mode = $(if ($adSwitch) { "All" } else { "CA" }) }
  elseif ($adSwitch -or $PSBoundParameters.ContainsKey("OutputPath")) { $Mode = "AD" }
}
try {
  if ($Mode -eq "Menu") {
    while ($true) {
      Show-Menu
      $answer = Read-Host "Выбор (можно несколько через запятую, например 5,7)"
      try { $sel = Resolve-Selection $answer; break } catch { Write-Host $_.Exception.Message -ForegroundColor Yellow }
    }
  } else {
    $wanted = @()
    if ($Mode -ne "AD") {
      $wanted = @("ca", "dc", "web")
      if ($PSBoundParameters.ContainsKey("Sections")) { $wanted = Resolve-Sections $Sections }
      if ($wanted.Count -eq 0) { throw "Не выбран ни один раздел данных ЦС: -Sections ca,dc,web" }
    }
    $sel = [pscustomobject]@{ Ad = ($Mode -ne "CA"); SkipComputerAcl = [bool]$SkipComputerAcl; SkipSysvol = [bool]$SkipSysvol; Sections = $wanted }
  }
  $picked = @($sel.Sections)

  Write-Step "Домен"
  $root = Get-ADRootDSE @ad
  $domain = Get-ADDomain @ad
  $netbios = $domain.NetBIOSName
  $pki = "CN=Public Key Services,CN=Services," + $root.configurationNamingContext

  $cas = @()
  $dcs = @()
  $urls = @()
  if ($picked -contains "ca" -or $picked -contains "web") {
    Write-Step "Центры сертификации"
    $cas = Get-CaList
    Write-Step ("  найдено: {0}" -f $cas.Count)
  }
  if ($picked -contains "dc") {
    Write-Step "Контроллеры домена"
    $dcs = @(Get-ADDomainController @ad -Filter * | ForEach-Object { [string]$_.HostName } | Sort-Object)
    Write-Step ("  найдено: {0}" -f $dcs.Count)
  }
  if ($picked -contains "web") { $urls = Get-WebUrls $cas }

  Write-Host ""
  Write-Host "План сбора" -ForegroundColor Green
  Write-Host ("  Запросы LDAP — контроллер {0}" -f $root.dnsHostName)
  if ($sel.Ad) {
    $what = "пользователи, компьютеры (" + $(if ($sel.SkipComputerAcl) { "без ACL" } else { "с ACL" }) + "), группы, OU, групповые политики"
    if (-not $sel.SkipSysvol) { $what += ", файлы GPO из SYSVOL (GptTmpl.inf, Registry.pol по белому списку, настройки GPP без паролей, аудит, скрипты) и права на папки GPO" }
    Write-Host ("  Выгрузка AD: {0}, шаблоны сертификатов и объекты PKI, доверенные домены, настройки домена и леса, PSO, зоны DNS, сайты и подсети" -f $what)
  }
  if ($picked -contains "ca") {
    Write-Host "  Настройки и права ЦС (certutil, при отказе — удалённый реестр):"
    if ($cas.Count -eq 0) { Write-Host "    центров сертификации в домене не найдено" }
    foreach ($ca in $cas) { Write-Host ("    {0} на {1}" -f $ca.Name, $ca.DnsName) }
  }
  if ($picked -contains "dc") {
    Write-Host "  Состояние контроллеров домена (удалённый реестр; CIM по WSMan, при отказе DCOM — SMB, службы, время загрузки):"
    foreach ($dc in $dcs) { Write-Host ("    {0}" -f $dc) }
  }
  if ($picked -contains "web") {
    Write-Host "  Веб-выдача (запрос без учётных данных):"
    if ($urls.Count -eq 0) { Write-Host "    адресов нет" }
    foreach ($u in $urls) { Write-Host ("    {0}" -f $u) }
  }
  if ($Mode -eq "Menu" -and -not $Yes) {
    $confirm = Read-Host "Продолжить? (y/n)"
    if ($confirm -notmatch '^\s*(y|yes|д|да)\s*$') { Write-Host "Отменено, файлы не записаны."; return }
  }

  $stamp = Get-Date -Format "yyyyMMdd-HHmm"
  $adName = "ad-{0}-{1}.json.gz" -f $netbios, $stamp
  $caName = "adca-{0}-{1}.json.gz" -f $netbios, $stamp
  $adPath = Join-Path $PWD.ProviderPath $adName
  $caPath = Join-Path $PWD.ProviderPath $caName
  if ($OutputPath) {
    # [System.IO.File] считает относительные пути от рабочего каталога процесса, а не от $PWD.
    $target = $OutputPath
    if (-not [System.IO.Path]::IsPathRooted($target)) { $target = Join-Path $PWD.ProviderPath $target }
    if ($OutputPath -match '[\\/]$' -or (Test-Path -LiteralPath $target -PathType Container)) {
      $adPath = Join-Path $target $adName
      $caPath = Join-Path $target $caName
    } elseif ($sel.Ad) {
      $adPath = $target
      $caPath = Join-Path (Split-Path -Parent $target) $caName
    } else { $caPath = $target }
  }

  $summary = New-Object System.Collections.Generic.List[string]
  if ($sel.Ad) {
    $export = Collect-Ad $sel.SkipComputerAcl $sel.SkipSysvol
    Write-GzipJson $export $adPath
    [void]$written.Add($adPath)
    [void]$summary.Add(("Выгрузка AD: {0} — объектов {1}, GPO с GptTmpl.inf {2}, имён SID {3}, размер {4:N0} байт" -f $adPath, $export.objects.Count, $export.sysvol.Count, $export.principals.Count, (Get-Item $adPath).Length))
  }
  if ($picked.Count -gt 0) {
    $caExport = Collect-Ca $picked $cas $dcs $urls
    Write-GzipJson $caExport $caPath
    [void]$written.Add($caPath)
    $failed = @($caExport.cas + $caExport.dcs + $caExport.web | Where-Object { $_.error }).Count
    [void]$summary.Add(("Данные ЦС: {0} — разделы {1}; центров {2}, контроллеров {3}, адресов {4}, с ошибкой {5}; размер {6:N0} байт" -f $caPath, ($picked -join ", "), $caExport.cas.Count, $caExport.dcs.Count, $caExport.web.Count, $failed, (Get-Item $caPath).Length))
  }

  Write-Host ""
  Write-Host "Готово." -ForegroundColor Green
  foreach ($line in $summary) { Write-Host ("  " + $line) -ForegroundColor Green }
  if ($script:warnings.Count -gt 0) { Write-Host ("Предупреждений: {0} (см. выше)" -f $script:warnings.Count) -ForegroundColor Yellow }
  Write-Host "Загрузите файлы в STools по одному: Active Directory → Настройки и данные → Загрузить выгрузку (то же поле для обоих файлов)."
} catch {
  # Где оборвалось: шаг, строка скрипта и стек — чтобы отказ можно было разобрать по одному выводу.
  Write-Host ""
  Write-Host ("Сбор прерван на шаге «{0}»: {1}" -f $script:stage, $_.Exception.Message) -ForegroundColor Red
  $pos = $_.InvocationInfo
  if ($pos -and $pos.ScriptLineNumber) { Write-Host ("  строка {0}: {1}" -f $pos.ScriptLineNumber, ([string]$pos.Line).Trim()) -ForegroundColor Red }
  if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
  if ($written.Count -gt 0) { Write-Host ("Записано до отказа: {0}" -f ($written -join ", ")) -ForegroundColor Yellow }
  else { Write-Host "Файлы не записаны." -ForegroundColor Red }
  throw
}
