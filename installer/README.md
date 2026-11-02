# Installer di AXCrypt (Windows, Inno Setup)

## Come generare `AXCrypt-Setup.exe`

1. Costruisci i binari di release:
   ```powershell
   cd I:\Archiviatore-cifrato
   cargo build --release
   ```
2. Compila l'installer (uno dei due modi):
   - **IDE**: apri `installer\axcrypt.iss` con Inno Setup e premi **Compile**.
   - **Terminale**:
     ```powershell
     & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\axcrypt.iss
     ```
3. Trovi il risultato in `installer\Output\AXCrypt-Setup.exe`. Quello è il file
   da copiare e lanciare sull'altra macchina.

L'installer: copia `axcrypt.exe` e `axcrypt-gui.exe` in Program Files, crea il
collegamento nel menu Start (e opzionalmente sul desktop), e — se scegli il
relativo task — aggiunge `axcrypt` al PATH.

## Binario davvero standalone (consigliato per distribuire)

Per impostazione predefinita i binari MSVC dipendono dal runtime Visual C++
(di solito già presente su Windows 10/11). Per non dipenderne affatto, linka il
CRT staticamente: il file `.cargo\config.toml` incluso nel progetto lo fa già.
Dopo averlo aggiunto o modificato, **ricostruisci** con `cargo build --release`.

## Alternative

- **Portatile**: senza installer, copi i due `.exe` sull'altra macchina (con il
  CRT statico sopra sono autonomi).
- **cargo-dist**: genera installer per Windows/macOS/Linux automaticamente a
  ogni release su GitHub (lo configuriamo nel passo "pubblicazione").
- **MSI**: `cargo install cargo-wix` poi `cargo wix` se preferisci un `.msi`.
