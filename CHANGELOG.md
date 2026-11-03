# Changelog

Tutte le modifiche rilevanti sono documentate qui. Il formato segue
[Keep a Changelog](https://keepachangelog.com/it/1.1.0/) e il progetto usa il
[Versionamento Semantico](https://semver.org/lang/it/).

## [0.6.1] - Non rilasciato

### Aggiunto
- **Packing e firma dei binari di release**. La pipeline comprime gli
  eseguibili con UPX (`installer/pack.ps1`) e li firma con una firma
  Authenticode SHA-256 + timestamp (`installer/sign.ps1`), installer compreso.
- `installer/make-test-cert.ps1`: certificato self-signed per provare la
  pipeline di firma in locale.
- `docs/SIGNING.md`: guida a packing, firma e scelta del certificato.

### Modificato
- `release.yml`: UPX + firma attivi solo quando è configurato un certificato
  (secret `SIGN_PFX_BASE64` / `SIGN_PFX_PASSWORD`); packing e firma viaggiano
  insieme, così senza certificato la release esce pulita (non compressa, non
  firmata) e non si rischiano falsi positivi degli antivirus. La versione
  dell'installer ora arriva dal tag.
- Installer: versione parametrica (`/DAppVersion=...`) e campi VersionInfo.

## [0.6.0] - 2026-11-03

### Aggiunto
- **Formato archivio v4** (`AXCRYPT4`): codifica binaria propria e documentata
  in `docs/FORMAT_SPEC.md`, senza `serde`/`bincode`.
- Indice più compatto: lunghezze a `u32` e compressione zstd prima della
  cifratura (oltre il 50% più piccolo su archivi con molti file).
- **Date di modifica** dei file salvate nell'archivio e ripristinate in
  estrazione.
- Test di robustezza: ogni byte alterato e ogni troncamento devono dare un
  errore pulito; fixture di un archivio v3 reale per i test di compatibilità.

### Modificato
- Gli archivi **v3 restano leggibili** (estrazione, `list`, `info`, `changepw`,
  `addkey`, `rmkey`, `repair`). I nuovi archivi sono sempre v4.
- I `.rec` v2 restano validi (stesso layout, ora codificato senza bincode).
- Rimosse le dipendenze `serde` e `bincode` dal core: cargo-audit non segnala
  più nulla nel core.

### Sicurezza
- Limiti massimi ai parametri Argon2id letti dagli slot (4 GiB, 32 iterazioni,
  16 lane). Prima un singolo bit alterato in uno slot poteva far tentare
  un'allocazione di decine di GiB (crash) o miliardi di iterazioni (blocco).
- Header e footer validati a taglia fissa prima di qualsiasi allocazione;
  corretto un possibile underflow nella lettura del footer di file malformati.

## [0.5.2] - 2026-11-03

### Modificato
- **GUI**: aggiornata a `eframe`/`egui` 0.36.2 (da 0.28) e `rfd` 0.17.2.
  Porting alle nuove API (`App::ui`, `Panel`, `CornerRadius`, `Frame::NONE`)
  mantenendo tema e funzioni invariati. Gli avvisi di cargo-audit sulla GUI
  scendono da 9 a 4: restano `ttf-parser` (font di egui, nessuna alternativa
  upstream) e `zbus_names`/`zvariant`/`zvariant_derive` (solo Linux, non
  compilati su Windows).

### Corretto
- GUI: i simboli del pallino di stato e della freccia del generatore password
  non erano presenti nei font di egui e apparivano come quadratini vuoti; ora
  il pallino è disegnato e la freccia usa un glifo supportato.

## [0.5.1] - 2026-11-03

### Modificato
- **Recovery record**: sostituita la libreria `reed-solomon-erasure` con
  `reed-solomon-simd` (mantenuta, più veloce). Rimuove dal core le dipendenze
  segnalate da cargo-audit: `lru` (unsound, RUSTSEC-2026-0253) e `instant`
  (non mantenuto, RUSTSEC-2024-0384).
- Granularità del recupero più fine: fino a 1024 blocchi dati (prima 200), così
  i danni sparsi consumano meno parità.
- Formato `.rec` **v2**: i `.rec` creati con la 0.5.0 vanno rigenerati con
  `axcrypt protect`. Gli archivi `.axc` non cambiano.
- zstd aggiornato alla 0.14.

### Sicurezza
- CI con permessi minimi (`contents: read`), Dependabot e audit delle
  dipendenze (cargo-audit) attivi.

## [0.5.0] - 2026-11-03

### Aggiunto
- **Core**: formato `.axc` con deduplicazione a blocchi (FastCDC) + zstd,
  cifratura autenticata XChaCha20-Poly1305, derivazione chiavi Argon2id, firma
  Ed25519 degli archivi.
- **Cifratura a busta (keyslot)**: chiave master casuale avvolta da
  password+keyfile; cambio password istantaneo e fino a 8 chiavi d'accesso.
- **Streaming**: pack/unpack a memoria limitata (~25 MB di picco anche su
  archivi oltre 1 GB), con tabella offset dei blocchi.
- **Recovery record**: parità Reed-Solomon in un sidecar `.rec` (`protect` /
  `repair`).
- **Generatore di password** con stima di robustezza.
- **CLI** `axcrypt`: keygen, makekeyfile, pack, unpack, list, info, changepw,
  addkey, rmkey, protect, repair.
- **GUI** egui/eframe (tema scuro, generatore integrato, operazioni in
  background).
- **Multithreading** (rayon) su compressione/cifratura dei blocchi.
- Installer Windows (Inno Setup), CI e pipeline di release su GitHub Actions.

### Sicurezza
- Chiavi e segreti azzerati in memoria (zeroize).
- Metadati (nomi file inclusi) cifrati; firma con verifica del firmatario fidato
  (`--trust`).

[0.5.1]: https://github.com/TexAlphaWolf/AXCrypt/releases/tag/v0.5.1
[0.5.0]: https://github.com/TexAlphaWolf/AXCrypt/releases/tag/v0.5.0
