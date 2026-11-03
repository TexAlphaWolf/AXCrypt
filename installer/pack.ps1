<#
.SYNOPSIS
    Comprime gli eseguibili di AXCrypt con UPX (packer).

.DESCRIPTION
    Riduce la dimensione dei binari e ne rende meno immediato il reverse
    engineering. NON è una protezione crittografica: la sicurezza del software
    sta nella chiave, non nella segretezza del codice.

    Attenzione: i file compressi con UPX sono talvolta segnalati come sospetti
    dagli antivirus (falsi positivi). Per questo il packing va sempre
    accompagnato dalla firma Authenticode (sign.ps1), che riduce i falsi
    positivi e toglie l'avviso di editore sconosciuto di SmartScreen.

    Ordine corretto della pipeline:  cargo build  →  pack.ps1  →  sign.ps1.
    Si comprime PRIMA e si firma DOPO: UPX non può comprimere un file già
    firmato senza invalidarne la firma.

    Idempotente: un file già compresso con UPX viene saltato.

.PARAMETER Files
    Percorsi degli .exe da comprimere.

.PARAMETER Level
    Livello di compressione UPX. Default: --best.

.EXAMPLE
    pwsh installer\pack.ps1 -Files target\release\axcrypt.exe,target\release\axcrypt-gui.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Files,
    [string]   $Level = '--best'
)

$ErrorActionPreference = 'Stop'

# Normalizza $Files: con "powershell -File script -Files a,b" la lista arriva
# come singola stringa "a,b". Qui la ri-dividiamo, così lo script funziona
# qualunque sia il modo di invocarlo.
$Files = $Files | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' }

$upx = Get-Command upx -ErrorAction SilentlyContinue
if (-not $upx) {
    throw "upx non trovato nel PATH. Installa con:  choco install upx -y   (oppure scaricalo da https://upx.github.io)."
}

foreach ($f in $Files) {
    if (-not (Test-Path -LiteralPath $f)) { throw "File non trovato: $f" }

    # UPX scrive messaggi normali su stderr; con ErrorActionPreference = Stop
    # Windows PowerShell 5.1 li scambia per errori e si ferma. Isoliamo le
    # chiamate native e decidiamo solo dal codice di uscita ($LASTEXITCODE).
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Salta i file già impacchettati (upx -t riesce solo sui file UPX).
        & $upx.Source -t $f *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Gia' compresso, salto: $f"
            continue
        }

        $before = (Get-Item -LiteralPath $f).Length
        & $upx.Source $Level '--lzma' $f *> $null
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $eap
    }
    if ($code -ne 0) { throw "upx ha fallito su $f (codice $code)." }
    $after = (Get-Item -LiteralPath $f).Length

    $pct = if ($before -gt 0) { [math]::Round(100 * $after / $before, 1) } else { 0 }
    Write-Host ("Compresso {0}: {1:N0} -> {2:N0} byte ({3}% dell'originale)" -f $f, $before, $after, $pct)
}
