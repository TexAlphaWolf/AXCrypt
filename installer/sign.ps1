<#
.SYNOPSIS
    Firma Authenticode uno o più file (.exe) di AXCrypt.

.DESCRIPTION
    Sceglie automaticamente il backend in base alle variabili d'ambiente
    presenti, in quest'ordine:

      1) PFX_BASE64 (+ PFX_PASSWORD)  → certificato .pfx passato come base64.
         È il percorso usato dalla CI tramite i secret di GitHub, e vale sia
         per un certificato commerciale esportabile sia per un self-signed.

      2) CERT_THUMBPRINT             → certificato già nello store di Windows
         (CurrentUser\My). Comodo per provare in locale con un self-signed
         creato da make-test-cert.ps1.

    Se nessuna delle due è impostata, NON firma: stampa un avviso e termina
    con successo, così la build di release continua a produrre binari non
    firmati. Usa -Require per farla invece fallire quando manca il certificato.

    La firma usa SHA-256 e un timestamp RFC-3161, così resta valida anche
    dopo la scadenza del certificato.

.PARAMETER Files
    Percorsi dei file da firmare.

.PARAMETER Require
    Se presente, l'assenza di un certificato è un errore (exit 1).

.EXAMPLE
    pwsh installer\sign.ps1 -Files target\release\axcrypt.exe,target\release\axcrypt-gui.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Files,
    [switch]   $Require
)

$ErrorActionPreference = 'Stop'

# Normalizza $Files: con "powershell -File script -Files a,b" la lista arriva
# come singola stringa "a,b". Qui la ri-dividiamo, così lo script funziona
# qualunque sia il modo di invocarlo.
$Files = $Files | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' }

# URL del timestamp server (RFC-3161, SHA-256). Sovrascrivibile via env.
$timestampUrl = if ($env:SIGN_TIMESTAMP_URL) { $env:SIGN_TIMESTAMP_URL }
                else { 'http://timestamp.digicert.com' }

function Find-SignTool {
    # signtool.exe fa parte del Windows SDK. Prende la versione x64 più recente.
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles        'Windows Kits\10\bin')
    ) | Where-Object { $_ -and (Test-Path $_) }

    $tool = foreach ($r in $roots) {
        Get-ChildItem -Path $r -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' }
    }
    $tool = $tool | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $tool) {
        throw "signtool.exe non trovato. Installa il Windows SDK (o i Build Tools con il componente 'Windows SDK')."
    }
    return $tool.FullName
}

function Invoke-SignTool {
    param([string] $SignTool, [string[]] $ToolArgs)
    & $SignTool @ToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "signtool ha restituito codice $LASTEXITCODE."
    }
}

# --- Scelta del backend ---------------------------------------------------
$mode = $null
if ($env:PFX_BASE64)      { $mode = 'pfx' }
elseif ($env:CERT_THUMBPRINT) { $mode = 'thumbprint' }

if (-not $mode) {
    $msg = "Nessun certificato configurato (PFX_BASE64 o CERT_THUMBPRINT): firma saltata."
    if ($Require) { Write-Error $msg; exit 1 }
    Write-Warning $msg
    exit 0
}

# Verifica che i file esistano prima di procedere.
foreach ($f in $Files) {
    if (-not (Test-Path -LiteralPath $f)) { throw "File da firmare non trovato: $f" }
}

$signtool = Find-SignTool
Write-Host "signtool: $signtool"
Write-Host "Timestamp: $timestampUrl"

$pfxPath = $null
try {
    $common = @('sign', '/fd', 'sha256', '/tr', $timestampUrl, '/td', 'sha256', '/v')

    if ($mode -eq 'pfx') {
        # Scrive il .pfx in un file temporaneo, lo usa, poi lo cancella.
        $pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) ("axcrypt-sign-{0}.pfx" -f ([guid]::NewGuid()))
        [System.IO.File]::WriteAllBytes($pfxPath, [System.Convert]::FromBase64String($env:PFX_BASE64))
        $signArgs = $common + @('/f', $pfxPath)
        if ($env:PFX_PASSWORD) { $signArgs += @('/p', $env:PFX_PASSWORD) }
        Write-Host "Firma con certificato .pfx ($($Files.Count) file)..."
    }
    else {
        $signArgs = $common + @('/sha1', $env:CERT_THUMBPRINT)
        Write-Host "Firma con certificato dallo store (thumbprint)..."
    }

    foreach ($f in $Files) {
        Write-Host " -> $f"
        Invoke-SignTool -SignTool $signtool -ToolArgs ($signArgs + @($f))
    }

    # Verifica le firme. /pa = policy Authenticode di default. Con un
    # certificato self-signed la verifica fallisce di proposito (la radice non
    # e' fidata): in quel caso avvisa soltanto, la firma c'e' comunque.
    foreach ($f in $Files) {
        & $signtool verify /pa /v $f
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Verifica non superata per $f (atteso con un certificato self-signed)."
        }
    }
    Write-Host "Firma completata."
}
finally {
    if ($pfxPath -and (Test-Path -LiteralPath $pfxPath)) {
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
}
