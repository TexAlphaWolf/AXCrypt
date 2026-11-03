# Changelog

Tutte le modifiche rilevanti sono documentate qui. Il formato segue
[Keep a Changelog](https://keepachangelog.com/it/1.1.0/) e il progetto usa il
[Versionamento Semantico](https://semver.org/lang/it/).

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

[0.5.0]: https://github.com/TexAlphaWolf/AXCrypt/releases/tag/v0.5.0
