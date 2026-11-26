$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$settingsPath = Join-Path $root 'config\settings.json'
$certPath = Join-Path $root 'certs\server.crt'

if (-not (Test-Path -LiteralPath $settingsPath)) {
    Write-Host "settings_missing=$settingsPath"
    exit 1
}

$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$uri = [Uri]$settings.server_url
$hostName = $uri.Host
$port = $uri.Port
Write-Host "server_url=$($settings.server_url)"
Write-Host "target=$hostName`:$port"
Write-Host "settings_written=$((Get-Item -LiteralPath $settingsPath).LastWriteTime.ToString('s'))"
Write-Host "local_time=$(Get-Date -Format s)"

$tcp = Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Host "tcp_reachable=$tcp"

if (Test-Path -LiteralPath $certPath) {
    $hash = (Get-FileHash -LiteralPath $certPath -Algorithm SHA256).Hash
    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    Write-Host "cert=$certPath"
    Write-Host "cert_sha256=$hash"
    Write-Host "cert_not_before=$($x509.NotBefore.ToString('s'))"
    Write-Host "cert_not_after=$($x509.NotAfter.ToString('s'))"
} else {
    Write-Host "cert_missing=$certPath"
}

$identityPath = Join-Path $root 'config\identity.blob'
if (Test-Path -LiteralPath $identityPath) {
    $identity = Get-Item -LiteralPath $identityPath
    Write-Host "identity_present=True"
    Write-Host "identity_bytes=$($identity.Length)"
    Write-Host "identity_written=$($identity.LastWriteTime.ToString('s'))"
} else {
    Write-Host "identity_present=False"
}

$healthUrl = "https://{0}:{1}/health" -f $hostName, $port
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curl) {
    $health = & curl.exe -k -s -o NUL -w "%{http_code}" --max-time 8 $healthUrl
    Write-Host "health_http=$health"
} else {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 8
        Write-Host "health_http=$($response.StatusCode)"
    } catch {
        Write-Host "health_error=$($_.Exception.Message)"
    }
}
