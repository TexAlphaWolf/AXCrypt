<#
.SYNOPSIS
    Crea un certificato di code signing SELF-SIGNED per provare in locale la
    pipeline di firma. NON serve per la distribuzione.

.DESCRIPTION
    Genera un certificato self-signed nello store CurrentUser\My e ne stampa il
    thumbprint, da passare a sign.ps1 via la variabile CERT_THUMBPRINT.

    Un certificato self-signed permette di verificare che firma e timestamp
    funzionino, ma NON toglie l'avviso di SmartScreen sugli altri PC: lì il
    certificato non è fidato. Per la distribuzione serve un certificato emesso
    da una CA pubblica (vedi docs/SIGNING.md).

.EXAMPLE
    pwsh installer\make-test-cert.ps1
    $env:CERT_THUMBPRINT = "<thumbprint stampato>"
    pwsh installer\sign.ps1 -Files target\release\axcrypt.exe
#>
[CmdletBinding()]
param(
    [string] $Subject = 'CN=AXCrypt Test (self-signed), O=Tex',
    [int]    $Years   = 3
)

$ErrorActionPreference = 'Stop'

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA -KeyLength 3072 `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($Years) `
    -HashAlgorithm SHA256

Write-Host ""
Write-Host "Certificato self-signed creato (solo per test locali)."
Write-Host "  Subject   : $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Scadenza  : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "Per firmare con questo certificato:"
Write-Host "  `$env:CERT_THUMBPRINT = '$($cert.Thumbprint)'"
Write-Host "  pwsh installer\sign.ps1 -Files target\release\axcrypt.exe,target\release\axcrypt-gui.exe"
Write-Host ""
Write-Host "Per esportarlo come .pfx (es. per i secret della CI):"
Write-Host "  `$pw = ConvertTo-SecureString 'password-forte' -AsPlainText -Force"
Write-Host "  Export-PfxCertificate -Cert 'Cert:\CurrentUser\My\$($cert.Thumbprint)' -FilePath test.pfx -Password `$pw"
