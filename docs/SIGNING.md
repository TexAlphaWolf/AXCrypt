# Packing e firma dei binari

Dalla versione 0.6.1 la pipeline di release può **comprimere** gli eseguibili
con UPX e **firmarli** con una firma Authenticode. Entrambi i passi sono
opzionali e la build funziona anche senza.

## Perché (e perché con cautela)

- **UPX** riduce la dimensione del binario e rende meno immediato leggerne il
  codice. Non è una protezione crittografica: la sicurezza di AXCrypt sta nella
  chiave, non nella segretezza del formato (che è pubblico).
- **Problema**: i file compressi con UPX sono spesso segnalati come sospetti
  dagli antivirus (falsi positivi). Per un software di cifratura è un danno.
- **La firma Authenticode** risolve gran parte del problema: lega il binario a
  un'identità verificata, riduce i falsi positivi e toglie l'avviso di "editore
  sconosciuto" di SmartScreen. Per questo packing e firma vanno **insieme**.

Ordine della pipeline (gestito da `release.yml`):

```
cargo build --release   →   pack.ps1 (UPX)   →   sign.ps1 (exe)
                        →   ISCC (installer)  →   sign.ps1 (installer)
```

Si comprime **prima** e si firma **dopo**: UPX non può comprimere un file già
firmato senza invalidarne la firma.

## Script

| Script | Cosa fa |
|--------|---------|
| `installer/pack.ps1` | comprime gli `.exe` con UPX (idempotente) |
| `installer/sign.ps1` | firma Authenticode (SHA-256 + timestamp RFC-3161) |
| `installer/make-test-cert.ps1` | crea un certificato self-signed per i test locali |

`sign.ps1` sceglie il backend dalle variabili d'ambiente:

- `PFX_BASE64` (+ `PFX_PASSWORD`): un certificato `.pfx` passato come base64.
  È il percorso usato dalla CI tramite i secret di GitHub.
- `CERT_THUMBPRINT`: un certificato già presente in `CurrentUser\My` (comodo in
  locale con un self-signed).
- Nessuna delle due: la firma viene **saltata** con un avviso (la build non
  fallisce). Con `-Require` l'assenza diventa un errore.

## Provare tutto in locale (certificato self-signed)

Un self-signed verifica che la pipeline funzioni, ma **non** toglie l'avviso di
SmartScreen sugli altri PC (lì il certificato non è fidato).

```powershell
cd I:\Archiviatore-cifrato
cargo build --release

# 1) crea il certificato di test e copia il thumbprint che stampa
pwsh installer\make-test-cert.ps1
$env:CERT_THUMBPRINT = "<thumbprint>"

# 2) comprimi e firma
pwsh installer\pack.ps1 -Files target\release\axcrypt.exe,target\release\axcrypt-gui.exe
pwsh installer\sign.ps1 -Files target\release\axcrypt.exe,target\release\axcrypt-gui.exe
```

Per vedere la firma: tasto destro sul file → Proprietà → scheda "Firme digitali".

## Firmare in release (certificato vero)

1. Procurati un certificato di **code signing** (vedi sotto) ed esportalo come
   `.pfx`.
2. Codificalo in base64 e aggiungilo ai secret del repository:
   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx")) | Set-Clipboard
   ```
   In GitHub: **Settings → Secrets and variables → Actions → New repository secret**
   - `SIGN_PFX_BASE64` = la stringa base64
   - `SIGN_PFX_PASSWORD` = la password del `.pfx`
3. Al prossimo tag `v*`, `release.yml` firma automaticamente i due `.exe` e
   l'installer. Senza i secret, la release esce ugualmente ma non firmata.

> Tieni il `.pfx` e la sua password fuori dal repository. Sono già coperti da
> `.gitignore` (`*.pfx`), ma non committarli mai.

## Che certificato serve

| Tipo | Toglie l'avviso SmartScreen | Note |
|------|------------------------------|------|
| **Self-signed** | No | solo per test locali |
| **OV** (Organization Validation) | Sì, dopo che il file si è fatto una "reputazione" | il più comune |
| **EV** (Extended Validation) | Sì, subito | reputazione immediata, costo maggiore |

Dal 2023 i certificati OV/EV non sono più esportabili come semplice `.pfx`: la
chiave privata deve stare su un token hardware o in un HSM cloud. Due strade
pratiche:

- **Azure Trusted Signing** (Microsoft): firma nel cloud, a consumo, economica.
  È l'opzione più adatta alla CI. Al posto del `.pfx` si usa l'action
  `azure/trusted-signing-action`; `release.yml` andrebbe adattato aggiungendo
  quel passo al posto della chiamata a `sign.ps1` per gli exe.
- **CA commerciale** (DigiCert, Sectigo, SSL.com, ...): emettono OV/EV con token
  o servizio di firma cloud (es. DigiCert KeyLocker, SSL.com eSigner), che
  espongono anch'essi una `signtool` compatibile.

Finché non hai un certificato vero, la pipeline resta pronta: basta che un
giorno aggiungi i secret e il prossimo tag produce una release firmata.
