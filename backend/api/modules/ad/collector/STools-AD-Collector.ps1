<#
.SYNOPSIS
  STools — сборщик выгрузки Active Directory (формат stools-ad/1).

.DESCRIPTION
  Запускается на машине в домене с модулем ActiveDirectory (RSAT) от
  учётной записи с правами чтения. Ничего не анализирует и не меняет:
  читает объекты, дескрипторы безопасности, GptTmpl.inf из SYSVOL и
  шаблоны сертификатов, складывает всё в один JSON (gzip). Файл
  загружается в STools → Active Directory → Настройки и данные.

.PARAMETER OutputPath
  Куда писать файл. По умолчанию ad-<NETBIOS>-<дата>.json.gz в текущем каталоге.

.PARAMETER Server
  Контроллер домена для запросов (по умолчанию — ближайший).

.PARAMETER SkipComputerAcl
  Не читать дескрипторы компьютеров (быстрее; проверка ACL компьютеров
  тогда пуста).

.PARAMETER SkipSysvol
  Не читать GptTmpl.inf из SYSVOL (проверка User Rights Assignment пуста).

.EXAMPLE
  .\STools-AD-Collector.ps1
  .\STools-AD-Collector.ps1 -Server dc01.corp.local -OutputPath C:\Temp\corp.json.gz
#>
#requires -Modules ActiveDirectory
[CmdletBinding()]
param(
  [string]$OutputPath,
  [string]$Server,
  [switch]$SkipComputerAcl,
  [switch]$SkipSysvol
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$FormatVersion = "stools-ad/1"
$CollectorVersion = "1.0"

$ad = @{}
if ($Server) { $ad["Server"] = $Server }

function Write-Step([string]$text) { Write-Host ("  " + $text) -ForegroundColor Cyan }

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

Write-Host "STools AD Collector $CollectorVersion (формат $FormatVersion)" -ForegroundColor Green

Write-Step "Домен"
$root = Get-ADRootDSE @ad
$domain = Get-ADDomain @ad
$domainObj = Get-ADObject @ad -Identity $domain.DistinguishedName -Properties "ms-DS-MachineAccountQuota", nTSecurityDescriptor
$netbios = $domain.NetBIOSName

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
$userProps = @("sAMAccountName","Name","objectSid","userAccountControl","lastLogonTimestamp","pwdLastSet","servicePrincipalName","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","adminCount")
Get-ADObject @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -Properties $userProps | ForEach-Object { Add-Account $_ "user" $false }

Write-Step "Компьютеры"
$compProps = $userProps + @("msDS-AllowedToActOnBehalfOfOtherIdentity")
if (-not $SkipComputerAcl) { $compProps += "nTSecurityDescriptor" }
Get-ADObject @ad -LDAPFilter "(objectClass=computer)" -Properties $compProps | ForEach-Object { Add-Account $_ "computer" (-not $SkipComputerAcl) }

Write-Step "Группы"
Get-ADObject @ad -LDAPFilter "(objectClass=group)" -Properties sAMAccountName,Name,objectSid,member,adminCount | ForEach-Object {
  $sid = SidString $_.objectSid
  $objects.Add(@{
    dn = $_.DistinguishedName; class = "group"; sid = $sid; sam = [string]$_.sAMAccountName; name = [string]$_.Name
    member = AsList $_.member; adminCount = AsInt $_.adminCount
  }) | Out-Null
  if ($sid) { Register-Principal $sid ("{0}\{1}" -f $netbios, $_.sAMAccountName) "group" }
}

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
  if (-not $SkipSysvol -and $_.gPCFileSysPath) {
    $inf = Join-Path $_.gPCFileSysPath "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (Test-Path $inf) {
      try { $sysvol[$_.DistinguishedName] = @{ "GptTmpl.inf" = [string](Get-Content -Path $inf -Raw) } } catch { }
    }
  }
}

Write-Step "Шаблоны сертификатов"
$tplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + $root.configurationNamingContext
Get-ADObject @ad -SearchBase $tplBase -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties displayName,pKIExtendedKeyUsage,"msPKI-Enrollment-Flag","msPKI-Certificate-Name-Flag","msPKI-RA-Signature","msPKI-Template-Schema-Version",nTSecurityDescriptor -ErrorAction SilentlyContinue | ForEach-Object {
  $objects.Add(@{
    dn = $_.DistinguishedName; class = "pKICertificateTemplate"; displayName = [string]$_.displayName
    pKIExtendedKeyUsage = AsList $_.pKIExtendedKeyUsage
    "msPKI-Enrollment-Flag" = AsInt $_."msPKI-Enrollment-Flag"
    "msPKI-Certificate-Name-Flag" = AsInt $_."msPKI-Certificate-Name-Flag"
    "msPKI-RA-Signature" = AsInt $_."msPKI-RA-Signature"
    "msPKI-Template-Schema-Version" = AsInt $_."msPKI-Template-Schema-Version"
    sd = ToBase64Sd $_.nTSecurityDescriptor
  }) | Out-Null
  Register-AceSids $_.nTSecurityDescriptor
}

$export = @{
  format = $FormatVersion
  collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  collector = @{ kind = "powershell"; version = $CollectorVersion; host = $env:COMPUTERNAME; account = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
  domain = $domainInfo
  guids = @{ extended_rights = $extRights; schema_attributes = $schemaAttrs }
  objects = $objects.ToArray()
  sysvol = $sysvol
  principals = $principals
}

if (-not $OutputPath) { $OutputPath = "ad-{0}-{1}.json.gz" -f $netbios, (Get-Date -Format "yyyyMMdd-HHmm") }
# [System.IO.File] считает относительные пути от рабочего каталога процесса, а не от $PWD.
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $PWD.ProviderPath $OutputPath }
Write-Step "Запись $OutputPath"
$json = $export | ConvertTo-Json -Depth 8 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$out = [System.IO.File]::Create($OutputPath)
try {
  $gz = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
  $gz.Write($bytes, 0, $bytes.Length)
  $gz.Dispose()
} finally { $out.Dispose() }

Write-Host ("Готово: объектов {0}, GPO с GptTmpl.inf {1}, имён SID {2}, размер {3:N0} байт" -f $objects.Count, $sysvol.Count, $principals.Count, (Get-Item $OutputPath).Length) -ForegroundColor Green
Write-Host "Загрузите файл в STools: Active Directory → Настройки и данные → Загрузить выгрузку."
