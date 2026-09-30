<#
.SYNOPSIS
  STools — сборщик Active Directory: выгрузка домена (формат stools-ad/1) и данные
  центров сертификации (формат stools-ad-ca/1).

.DESCRIPTION
  Запускается на машине в домене с модулем ActiveDirectory (RSAT). Ничего не
  анализирует и не меняет.

  Выгрузка AD: объекты, дескрипторы безопасности, GptTmpl.inf из SYSVOL,
  шаблоны сертификатов, центры сертификации и контейнеры PKI, политики выдачи,
  доверенные домены — один JSON (gzip), ad-<NETBIOS>-<дата>.json.gz. Хватает
  прав чтения каталога.

  Данные ЦС (их по LDAP не прочитать, STools сам их не собирает):
    ca  — флаги и права каждого ЦС (certutil, при отказе — удалённый реестр);
          нужны права администратора ЦС или локального администратора сервера ЦС;
    dc  — два значения реестра каждого контроллера домена (удалённый реестр);
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
  Не читать GptTmpl.inf из SYSVOL (проверка User Rights Assignment пуста).

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
$CollectorVersion = "2.0"

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

# Имена SID: собираются из ACE и самих объектов, чтобы анализатор не
# ходил в домен за именами.
$principals = @{}
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
  Write-Host "6  Данные ЦС: реестр контроллеров домена"
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

function Collect-Ad([bool]$noComputerAcl, [bool]$noSysvol) {
  Write-Step "Свойства домена"
  $domainObj = Get-ADObject @ad -Identity $domain.DistinguishedName -Properties "ms-DS-MachineAccountQuota", nTSecurityDescriptor
  $domainInfo = @{
    dns_root = $domain.DNSRoot
    dn = $domain.DistinguishedName
    netbios = $netbios
    sid = $domain.DomainSID.Value
    configuration_dn = $root.configurationNamingContext
    schema_dn = $root.schemaNamingContext
    machine_account_quota = AsInt $domainObj."ms-DS-MachineAccountQuota"
    functional_level = [string]$domain.DomainMode
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
    }
    if ($class -eq "computer") {
      $rec["allowedToActOnBehalf"] = ToBase64Sd $o."msDS-AllowedToActOnBehalfOfOtherIdentity"
      if ($o."msDS-AllowedToActOnBehalfOfOtherIdentity") { Register-AceSids $o."msDS-AllowedToActOnBehalfOfOtherIdentity" }
      if ($withSd) { $rec["sd"] = ToBase64Sd $o.nTSecurityDescriptor; Register-AceSids $o.nTSecurityDescriptor }
    }
    if ($sid) { Register-Principal $sid ("{0}\{1}" -f $netbios, $o.sAMAccountName) $class }
    $objects.Add($rec) | Out-Null
  }

  Write-Step "Пользователи"
  $n0 = $objects.Count
  $userProps = @("sAMAccountName","Name","objectSid","userAccountControl","lastLogonTimestamp","pwdLastSet","servicePrincipalName","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","adminCount","altSecurityIdentities")
  Get-ADObject @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -Properties $userProps | ForEach-Object { Add-Account $_ "user" $false }
  Write-Step ("  пользователей: {0}" -f ($objects.Count - $n0))

  Write-Step "Компьютеры"
  $n0 = $objects.Count
  $compProps = $userProps + @("msDS-AllowedToActOnBehalfOfOtherIdentity")
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

  Write-Step "Корень домена, AdminSDHolder, OU"
  $objects.Add(@{ dn = $domain.DistinguishedName; class = "domainDNS"; sid = $domain.DomainSID.Value; sd = ToBase64Sd $domainObj.nTSecurityDescriptor }) | Out-Null
  Register-AceSids $domainObj.nTSecurityDescriptor
  $holder = Get-ADObject @ad -Identity ("CN=AdminSDHolder,CN=System," + $domain.DistinguishedName) -Properties nTSecurityDescriptor
  $objects.Add(@{ dn = $holder.DistinguishedName; class = "container"; sd = ToBase64Sd $holder.nTSecurityDescriptor }) | Out-Null
  Register-AceSids $holder.nTSecurityDescriptor
  Get-ADObject @ad -LDAPFilter "(objectClass=organizationalUnit)" -Properties nTSecurityDescriptor | ForEach-Object {
    $objects.Add(@{ dn = $_.DistinguishedName; class = "organizationalUnit"; sd = ToBase64Sd $_.nTSecurityDescriptor }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
  }

  Write-Step "Групповые политики"
  $sysvol = @{}
  Get-ADObject @ad -SearchBase ("CN=Policies,CN=System," + $domain.DistinguishedName) -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName,gPCFileSysPath,nTSecurityDescriptor | ForEach-Object {
    $objects.Add(@{ dn = $_.DistinguishedName; class = "groupPolicyContainer"; displayName = [string]$_.displayName; gpcFileSysPath = [string]$_.gPCFileSysPath; sd = ToBase64Sd $_.nTSecurityDescriptor }) | Out-Null
    Register-AceSids $_.nTSecurityDescriptor
    if (-not $noSysvol -and $_.gPCFileSysPath) {
      $inf = Join-Path $_.gPCFileSysPath "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
      if (Test-Path $inf) {
        try { $sysvol[$_.DistinguishedName] = @{ "GptTmpl.inf" = [string](Get-Content -Path $inf -Raw) } } catch { }
      }
    }
  }
  Write-Step ("  GPO с GptTmpl.inf: {0}" -f $sysvol.Count)

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
  Get-AdOptional "доверенные домены" @{ SearchBase = "CN=System," + $domain.DistinguishedName; SearchScope = "OneLevel"; LDAPFilter = "(objectClass=trustedDomain)"; Properties = @("flatName", "securityIdentifier", "trustAttributes") } | ForEach-Object {
    $trustSid = $null
    if ($_.securityIdentifier) {
      try { $trustSid = SidFromBytes ([byte[]]$_.securityIdentifier) } catch { }
    }
    $objects.Add(@{
      dn = $_.DistinguishedName; class = "trustedDomain"; flatName = [string]$_.flatName; sid = $trustSid
      trustAttributes = AsInt $_.trustAttributes
    }) | Out-Null
  }
  Write-Step ("  доверенных доменов: {0}" -f ($objects.Count - $n0))

  # Что не прочитано: анализатор показывает это в «не проверено». Отказ по центрам сертификации
  # мог прийти дважды (план и выгрузка) — повторы убираются.
  $notes = @()
  if ($noSysvol) { $notes += "чтение SYSVOL выключено (-SkipSysvol)" }
  $notes += @($script:warnings | Select-Object -Unique)

  return @{
    format = $FormatVersion
    collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    collector = @{ kind = "powershell"; version = $CollectorVersion; host = $env:COMPUTERNAME; account = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME); notes = [string[]]$notes }
    domain = $domainInfo
    guids = @{ extended_rights = $extRights; schema_attributes = $schemaAttrs }
    objects = $objects.ToArray()
    sysvol = $sysvol
    principals = $principals
  }
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

function Get-DcBinding([string]$dc) {
  $rec = [ordered]@{ host = $dc; strong_binding = $null; mapping_methods = $null; error = "" }
  try {
    $kdc = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Services\Kdc" @("StrongCertificateBindingEnforcement")
    if ($kdc) { $rec.strong_binding = AsDword $kdc.StrongCertificateBindingEnforcement }
    $schannel = Read-RemoteRegistry $dc "SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" @("CertificateMappingMethods")
    if ($schannel) { $rec.mapping_methods = AsDword $schannel.CertificateMappingMethods }
  } catch { $rec.error = ErrorText $_ }
  return $rec
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
    Write-Step "Реестр контроллеров домена"
    foreach ($dc in $dcs) {
      $r = Get-DcBinding $dc
      $dcRecs.Add($r)
      if ($r.error) { Add-Warning ("контроллер {0}: {1}" -f $dc, $r.error) }
      else { Write-Step ("  {0}: привязка {1}, сопоставление {2}" -f $dc, $r.strong_binding, $r.mapping_methods) }
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
    if (-not $sel.SkipSysvol) { $what += ", GptTmpl.inf из SYSVOL" }
    Write-Host ("  Выгрузка AD: {0}, шаблоны сертификатов и объекты PKI, доверенные домены" -f $what)
  }
  if ($picked -contains "ca") {
    Write-Host "  Настройки и права ЦС (certutil, при отказе — удалённый реестр):"
    if ($cas.Count -eq 0) { Write-Host "    центров сертификации в домене не найдено" }
    foreach ($ca in $cas) { Write-Host ("    {0} на {1}" -f $ca.Name, $ca.DnsName) }
  }
  if ($picked -contains "dc") {
    Write-Host "  Реестр контроллеров домена (удалённый реестр, два значения):"
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
