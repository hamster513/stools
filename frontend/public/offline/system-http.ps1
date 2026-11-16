# Private subprocess bridge for download-stools.py. Compatible with Windows PowerShell 5.1/PS7.
# Request/response/metadata paths belong to one caller-created private temporary directory.
# HTTP statuses (including 304/4xx/5xx) are results; failures use fixed codes and exit 1.
param([string]$RequestFile)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$script:failureCode = 'invalid_request'
$metadataPath = $null
$responsePath = $null
$outputPart = $null
$createdResponse = $false
$cancellation = $null
$exitCode = 1

function Stop-Transport([string]$Code) {
    $script:failureCode = $Code
    throw $Code
}

function Get-HttpUri([string]$Value) {
    $uri = $null
    if ($Value -match '[\x00-\x20\x7f]' -or $Value.Contains('\') -or
        -not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https') -or -not $uri.Host -or $uri.UserInfo) {
        Stop-Transport 'invalid_url'
    }
    return $uri
}

function Get-NewOutputPath([string]$Value, [string]$Directory) {
    if (-not $Value -or -not [IO.Path]::IsPathRooted($Value)) {
        Stop-Transport 'invalid_output_path'
    }
    $full = [IO.Path]::GetFullPath($Value)
    if ([IO.Path]::GetDirectoryName($full) -ne $Directory -or
        [IO.File]::Exists($full) -or [IO.Directory]::Exists($full) -or
        (Test-Path -LiteralPath $full)) {
        Stop-Transport 'invalid_output_path'
    }
    return $full
}

function Write-Metadata($Value) {
    $part = Join-Path ([IO.Path]::GetDirectoryName($metadataPath)) ([Guid]::NewGuid().ToString() + '.part')
    $stream = $null
    $writer = $null
    try {
        $stream = [IO.File]::Open($part, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
        $writer.Write(($Value | ConvertTo-Json -Compress -Depth 6))
        $writer.Dispose()
        $writer = $null
        $stream = $null
        [IO.File]::Move($part, $metadataPath)
    } finally {
        if ($writer) { $writer.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ([IO.File]::Exists($part)) { [IO.File]::Delete($part) }
    }
}

function Get-ProxyEnvironment([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name.ToLowerInvariant())
    if (-not $value) { $value = [Environment]::GetEnvironmentVariable($Name.ToUpperInvariant()) }
    return $value
}

function Test-EnvironmentBypass([Uri]$Uri) {
    $bypass = Get-ProxyEnvironment 'no_proxy'
    foreach ($entry in ($bypass -split ',')) {
        $entry = $entry.Trim()
        if (-not $entry) { continue }
        if ($entry -eq '*') { return $true }
        # Parse optional ports and IPv6 literals without interpreting a bypass entry as a regex.
        $bypassHost = $entry
        $port = $null
        if ($entry -match '^\[([^\]]+)\](?::([0-9]+))?$') {
            $bypassHost = $Matches[1]
            $port = $Matches[2]
        } elseif ($entry -match '^([^:]+):([0-9]+)$') {
            $bypassHost = $Matches[1]
            $port = $Matches[2]
        }
        if ($port -and [int]$port -ne $Uri.Port) { continue }
        $bypassHost = $bypassHost.TrimStart('.').ToLowerInvariant()
        $destination = $Uri.DnsSafeHost.Trim('[', ']').ToLowerInvariant()
        if ($destination -eq $bypassHost -or $destination.EndsWith('.' + $bypassHost)) { return $true }
    }
    return $false
}

function Get-ConfiguredProxy([Uri]$Uri, [bool]$Direct) {
    if ($Direct -or (Test-EnvironmentBypass $Uri)) {
        return @{ proxy = $null; url = $null; bypassed = $true }
    }
    $address = Get-ProxyEnvironment ($Uri.Scheme + '_proxy')
    if (-not $address) { $address = Get-ProxyEnvironment 'all_proxy' }
    if ($address) {
        if ($address -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $address = 'http://' + $address }
        $proxyUri = $null
        if (-not [Uri]::TryCreate($address, [UriKind]::Absolute, [ref]$proxyUri) -or
            $proxyUri.Scheme -notin @('http', 'https') -or -not $proxyUri.Host -or
            $proxyUri.Query -or $proxyUri.Fragment -or $proxyUri.AbsolutePath -ne '/') {
            Stop-Transport 'invalid_proxy'
        }
        $builder = [UriBuilder]::new($proxyUri)
        $builder.UserName = ''
        $builder.Password = ''
        $proxy = [Net.WebProxy]::new($builder.Uri)
        if ($proxyUri.UserInfo) {
            $parts = $proxyUri.UserInfo.Split(@(':'), 2)
            $password = ''
            if ($parts.Length -gt 1) { $password = [Uri]::UnescapeDataString($parts[1]) }
            $proxy.Credentials = [Net.NetworkCredential]::new([Uri]::UnescapeDataString($parts[0]), $password)
        } else {
            $proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
        }
        # This URL may contain env credentials: it is returned only in the private metadata file.
        return @{ proxy = $proxy; url = $proxyUri.AbsoluteUri; bypassed = $false }
    }
    # Windows Internet Options: automatic discovery, PAC, manual proxy and system bypass rules.
    $proxy = [Net.WebRequest]::GetSystemWebProxy()
    $proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
    $bypassed = $proxy.IsBypassed($Uri)
    $resolved = $proxy.GetProxy($Uri)
    if ($bypassed -or -not $resolved -or $resolved.AbsoluteUri -eq $Uri.AbsoluteUri) {
        return @{ proxy = $null; url = $null; bypassed = $true }
    }
    return @{ proxy = $proxy; url = $resolved.AbsoluteUri; bypassed = $false }
}

try {
    if (-not $RequestFile -or -not [IO.Path]::IsPathRooted($RequestFile) -or
        (Get-Item -LiteralPath $RequestFile).Length -gt 65536) {
        Stop-Transport 'invalid_request'
    }
    $requestPath = [IO.Path]::GetFullPath($RequestFile)
    $directory = [IO.Path]::GetDirectoryName($requestPath)
    $request = Get-Content -LiteralPath $requestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $metadataPath = Get-NewOutputPath $request.metadata_path $directory
    $uri = Get-HttpUri $request.url
    if ($request.action -notin @('fetch', 'resolve_proxy') -or $request.no_proxy -isnot [bool]) {
        Stop-Transport 'invalid_request'
    }
    Add-Type -AssemblyName System.Net.Http
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Legacy Windows PowerShell defaults can exclude TLS 1.2. This affects this process only.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    $script:failureCode = 'proxy_error'
    if ($request.action -eq 'resolve_proxy') {
        $configuration = Get-ConfiguredProxy $uri $request.no_proxy
        Write-Metadata @{ proxy = $configuration.url; bypassed = $configuration.bypassed }
    } else {
        $script:failureCode = 'invalid_request'
        $responsePath = Get-NewOutputPath $request.response_path $directory
        if ($responsePath -eq $metadataPath) { Stop-Transport 'invalid_output_path' }
        $maxBytes = [long]$request.max_bytes
        $timeout = [double]$request.timeout
        if ($maxBytes -le 0 -or $maxBytes -gt [long]::MaxValue / 2 -or
            $timeout -le 0 -or $timeout -gt 3600 -or [double]::IsNaN($timeout)) {
            Stop-Transport 'invalid_request'
        }
        $headers = @{}
        foreach ($property in $request.headers.PSObject.Properties) {
            $name = $property.Name
            $value = [string]$property.Value
            if ($name -notmatch '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$' -or
                $name -in @('Host', 'Proxy-Authorization', 'Content-Length', 'Transfer-Encoding') -or
                $value -match '[\x00-\x1f\x7f]') { Stop-Transport 'invalid_headers' }
            $headers[$name] = $value
        }
        $elapsed = [Diagnostics.Stopwatch]::StartNew()
        $cancellation = [Threading.CancellationTokenSource]::new()
        $cancellation.CancelAfter([TimeSpan]::FromSeconds($timeout))
        for ($redirects = 0; $redirects -le 5; $redirects++) {
            $handler = $null
            $client = $null
            $message = $null
            $response = $null
            $inputStream = $null
            $outputStream = $null
            try {
                $script:failureCode = 'proxy_error'
                $configuration = Get-ConfiguredProxy $uri $request.no_proxy
                $script:failureCode = 'transport_error'
                $handler = [Net.Http.HttpClientHandler]::new()
                $handler.AllowAutoRedirect = $false
                $handler.UseCookies = $false
                $handler.UseDefaultCredentials = $false
                if ($configuration.bypassed) {
                    $handler.UseProxy = $false
                } else {
                    $handler.UseProxy = $true
                    $handler.Proxy = $configuration.proxy
                    if ($handler.PSObject.Properties['DefaultProxyCredentials']) {
                        $handler.DefaultProxyCredentials = [Net.CredentialCache]::DefaultNetworkCredentials
                    }
                }
                $client = [Net.Http.HttpClient]::new($handler)
                $client.Timeout = [TimeSpan]::FromSeconds($timeout)
                $message = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
                foreach ($name in $headers.Keys) {
                    if (-not $message.Headers.TryAddWithoutValidation($name, [string]$headers[$name])) {
                        Stop-Transport 'invalid_headers'
                    }
                }
                $response = $client.SendAsync($message, [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                    $cancellation.Token).GetAwaiter().GetResult()
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308) -and $response.Headers.Location) {
                    if ($redirects -ge 5) { Stop-Transport 'redirect_limit' }
                    $next = Get-HttpUri ([Uri]::new($uri, $response.Headers.Location).AbsoluteUri)
                    if ($uri.Scheme -eq 'https' -and $next.Scheme -ne 'https') {
                        Stop-Transport 'unsafe_redirect'
                    }
                    if ($next.GetLeftPart([UriPartial]::Authority) -ne $uri.GetLeftPart([UriPartial]::Authority)) {
                        # Treat custom API-key headers as sensitive too when an origin changes.
                        $forward = @{}
                        foreach ($name in $headers.Keys) {
                            if ($name -in @('User-Agent', 'Accept', 'Accept-Encoding', 'If-None-Match', 'If-Modified-Since')) {
                                $forward[$name] = $headers[$name]
                            }
                        }
                        $headers = $forward
                    }
                    $uri = $next
                    continue
                }
                if ($status -ne 304 -and $response.Content.Headers.ContentLength -gt $maxBytes) {
                    Stop-Transport 'response_too_large'
                }
                $responseHeaders = @{}
                foreach ($header in $response.Headers) {
                    $responseHeaders[$header.Key.ToLowerInvariant()] = $header.Value -join ', '
                }
                foreach ($header in $response.Content.Headers) {
                    $responseHeaders[$header.Key.ToLowerInvariant()] = $header.Value -join ', '
                }
                $outputPart = Join-Path $directory ('body-' + [Guid]::NewGuid().ToString() + '.part')
                $outputStream = [IO.File]::Open($outputPart, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $buffer = New-Object byte[] 65536
                $total = [long]0
                while ($true) {
                    # .NET Framework streams may not cancel an in-flight async read. Bound the wait too.
                    $remainingMs = [int][Math]::Ceiling($timeout * 1000 - $elapsed.Elapsed.TotalMilliseconds)
                    if ($remainingMs -le 0) { Stop-Transport 'timeout' }
                    $readTask = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token)
                    if (-not $readTask.Wait($remainingMs)) { Stop-Transport 'timeout' }
                    $read = $readTask.GetAwaiter().GetResult()
                    if ($read -eq 0) { break }
                    $total += $read
                    if ($total -gt $maxBytes) { Stop-Transport 'response_too_large' }
                    $outputStream.Write($buffer, 0, $read)
                }
                $outputStream.Dispose()
                $outputStream = $null
                [IO.File]::Move($outputPart, $responsePath)
                $outputPart = $null
                $createdResponse = $true
                Write-Metadata @{ status = $status; headers = $responseHeaders; final_url = $uri.AbsoluteUri; bytes = $total }
                break
            } finally {
                if ($outputStream) { $outputStream.Dispose() }
                if ($inputStream) { $inputStream.Dispose() }
                if ($response) { $response.Dispose() }
                if ($message) { $message.Dispose() }
                if ($client) { $client.Dispose() } elseif ($handler) { $handler.Dispose() }
            }
        }
    }
    $exitCode = 0
} catch {
    if ($cancellation -and $cancellation.IsCancellationRequested) { $script:failureCode = 'timeout' }
    if ($createdResponse -and [IO.File]::Exists($responsePath)) { [IO.File]::Delete($responsePath) }
    if ($metadataPath -and -not [IO.File]::Exists($metadataPath)) {
        try { Write-Metadata @{ error = $script:failureCode } } catch { }
    }
    # Never print exceptions: .NET error messages can contain URLs, proxy credentials or headers.
} finally {
    if ($cancellation) { $cancellation.Dispose() }
    if ($outputPart -and [IO.File]::Exists($outputPart)) { [IO.File]::Delete($outputPart) }
}
exit $exitCode
