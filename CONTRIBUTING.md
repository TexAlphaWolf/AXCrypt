# Contributi

AXCrypt è un **progetto proprietario** (vedi [`LICENSE`](LICENSE)). Il codice è
pubblicato a scopo di consultazione e valutazione.

## Contributi di codice

Non sono accettati contributi esterni (pull request, fork, patch) senza previo
accordo scritto con il titolare del progetto. Le pull request non concordate
verranno chiuse.

## Segnalazioni

Le segnalazioni sono benvenute tramite **Issue**:

- **Bug**: usa il template "Segnalazione bug" e includi passi per riprodurre,
  comportamento atteso e ottenuto, versione e sistema operativo.
- **Idee / richieste**: usa il template "Richiesta funzionalità".
- **Vulnerabilità di sicurezza**: NON aprire una issue pubblica — segui
  [`SECURITY.md`](SECURITY.md).

## Build e test (per chi è autorizzato)

```bash
cargo build --release          # core + CLI + GUI
cargo test -p axcrypt-core     # suite del core
cargo fmt --all                # formattazione
cargo clippy -p axcrypt-core   # lint
```
