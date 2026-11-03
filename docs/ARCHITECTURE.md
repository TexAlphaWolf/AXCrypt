# Architettura di AXCrypt

## Workspace

Monorepo Cargo con tre crate:

```
axcrypt/
├─ Cargo.toml              workspace
├─ rust-toolchain.toml     toolchain stable MSVC
├─ docs/
│  ├─ FORMAT_SPEC.md       specifica del formato .axc
│  └─ ARCHITECTURE.md      questo file
└─ crates/
   ├─ core/                libreria: tutta la logica (formato, crypto, I/O)
   ├─ cli/                 binario a riga di comando (axcrypt)
   └─ gui/                 interfaccia grafica (fase 2, scheletro)
```

Il **core** non conosce né la CLI né la GUI: espone un'API pulita. Entrambi i
front-end (CLI ora, GUI dopo) la riusano. È qui il "mix sensato" di linguaggi
di cui parlavamo: un core sicuro e un'interfaccia separata — non codice
offuscato a mano.

## Moduli del core

| Modulo         | Responsabilità                                                      |
|----------------|--------------------------------------------------------------------|
| `error.rs`     | Tipo d'errore unico (`AxError`) con `thiserror`.                    |
| `format.rs`    | Costanti, `CoreHeader`, `Footer`, `ArgonParams`, (de)serializzazione.|
| `keys.rs`      | Argon2id (KEK), combinazione keyfile, MFK, sottochiavi dati.        |
| `keyslot.rs`   | Cifratura a busta: slot che avvolgono la MFK, MAC, apertura.        |
| `crypto.rs`    | Wrapper AEAD (XChaCha20-Poly1305) e firma/verifica Ed25519.        |
| `chunk.rs`     | FastCDC + mappa di deduplicazione `hash → index`.                  |
| `compress.rs`  | zstd con fallback "grezzo" per blocchi incomprimibili.             |
| `archive.rs`   | pack/unpack (multithread rayon), read_index, changepw/addkey/rmkey. |
| `recovery.rs`  | Recovery record: parità Reed-Solomon in un sidecar `.rec`.          |
| `identity.rs`  | Generazione/caricamento della coppia di chiavi di firma.           |
| `lib.rs`       | Riespone l'API pubblica + suite di test.                           |

## Pipeline dati (PACK)

```
file ─► FastCDC ─► [blocco] ─► BLAKE3 ─► nuovo? ──no──► riusa indice (dedup)
                                   │ sì
                                   ▼
                         zstd (o grezzo) ─► XChaCha20-Poly1305 ─► ChunkRecord
```

Alla fine: indice cifrato (XChaCha20-Poly1305 con `index_key`) + footer + firma
Ed25519 sull'intero file.

## Scelte di dipendenze (stabili e compatibili)

| Crate               | Scopo                         |
|---------------------|-------------------------------|
| `zstd`              | compressione                  |
| `chacha20poly1305`  | AEAD XChaCha20-Poly1305       |
| `argon2`            | KDF Argon2id                  |
| `blake3`            | hash + keyed-hash + derive_key|
| `ed25519-dalek`     | firma                         |
| `fastcdc`           | chunking content-defined      |
| `reed-solomon-simd` | parità del recovery record    |
| `bincode` + `serde` | serializzazione indice/header |
| `zeroize`           | azzeramento chiavi in memoria |
| `rand`              | sali, nonce, generazione chiavi|
| `clap` (cli)        | parsing argomenti             |
| `rpassword` (cli)   | prompt password nascosto      |
| `anyhow` (cli)      | gestione errori lato comando  |

Le versioni esatte sono fissate in ogni `Cargo.toml`. Criterio: ultima versione
**stabile e compatibile** con il resto dello stack, non l'ultimissima in
assoluto.

## Roadmap

1. **v0.1** — core + CLI: pack/unpack/list/info/keygen, dedup, zstd, AEAD,
   firma, password+keyfile. ✓ fatto
2. **v0.2 (questa)** — cifratura a busta (keyslot), `changepw`/`addkey`/`rmkey`,
   multithreading (rayon) su pack/unpack. ✓ fatto
3. **v0.3 (questa)** — pack/unpack a streaming (memoria limitata, regge archivi
   oltre la RAM); tabella offset dei blocchi per l'accesso casuale. ✓ fatto
4. **v0.4 (questa)** — recovery record (Reed-Solomon) in sidecar `.rec`:
   comandi `protect`/`repair`. ✓ fatto
5. **v0.5 (questa)** — GUI egui/eframe che riusa il core (schede Crea/Estrai/
   Chiavi/Recupero, operazioni su thread in background). ✓ fatto
6. **Release** — strip simboli (già attivo) + packer/obfuscator sul binario.

## Recovery record (.rec)

Sidecar separato dall'archivio (che resta intatto e firmato). L'archivio è
diviso in `data_count` blocchi (fino a 1024, di dimensione pari); si calcolano
`parity_count` blocchi di parità Reed-Solomon con `reed-solomon-simd` (GF(2^16),
codifica O(n log n)) e un hash breve (BLAKE3, 16 byte) per ogni blocco. In
`repair` i blocchi con hash non combaciante sono trattati come "cancellati" e
ricostruiti dalla parità, finché i blocchi dati danneggiati sono al massimo
quanti i blocchi di parità rimasti integri. Blocchi più piccoli rendono più
"economici" i danni sparsi: ogni blocco danneggiato consuma un blocco di parità.

Formato `.rec` v2 (magic `AXCREC2`). I `.rec` v1, creati con la vecchia libreria
`reed-solomon-erasure`, vengono rifiutati: rigenerali con `protect`. Gli archivi
`.axc` non cambiano. `protect`/`repair` lavorano in memoria (a differenza di
pack/unpack).

> Nota: lo strumento `cargo run --release --example bench_mem -p axcrypt-core`
> misura il picco di RAM del pack, utile per verificare lo streaming.

## Nota sul binario "difficile da reversare"

Non si ottiene mescolando linguaggi nel sorgente: si ottiene **dopo** la
compilazione, sul binario di release, con:

- `strip` dei simboli (`[profile.release] strip = "symbols"`),
- `panic = "abort"`, LTO, `opt-level = "z"` per un binario più compatto,
- un packer/obfuscator esterno (es. UPX per il packing; strumenti di
  offuscamento del control-flow se vorrai spingerti oltre).

Resta vero che un reverse engineer determinato arriva comunque al formato: per
questo la **sicurezza reale sta nella chiave**, non nell'offuscamento.
