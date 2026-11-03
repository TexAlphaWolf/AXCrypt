# Specifica del formato `.axc` (AXCrypt Archive)

Versione formato: **4** (scritta dalla 0.6.0). La **v3** resta leggibile.
Magic: `AXCRYPT4` (v4), `AXCRYPT3` (v3, solo lettura).

> Tutti gli interi sono **little-endian**. Tutte le primitive crittografiche
> sono standard e verificate: nessun algoritmo inventato in casa. La sicurezza
> deriva **interamente dalla chiave** (principio di Kerckhoffs), non dalla
> segretezza del formato. Questo documento è pubblico di proposito.

## Novità della v4

- **Codifica binaria propria** (niente serde/bincode): layout documentato qui
  sotto, decoder difensivo (limiti su ogni lunghezza, niente byte in eccesso).
- **Indice compatto**: lunghezze a `u32` invece di `u64`, poi compresso con
  zstd prima della cifratura.
- **Data di modifica** dei file salvata e ripristinata in estrazione.
- **Validazione rigida** prima della firma: header e footer a taglia fissa,
  regione keyslot in posizione fissa, parametri Argon2id entro limiti massimi.

Gli archivi v3 si aprono, si estraggono e accettano `changepw`/`addkey`/`rmkey`
(restando v3). Ricrearli in v4 serve solo per avere le date di modifica.

## Cifratura a busta (envelope)

Una **chiave master casuale** (MFK, 32 byte) cifra tutti i dati. La MFK non
deriva dalla password: viene **avvolta** da una o più password/keyfile in una
**regione keyslot**. Vantaggi:

- **Cambiare password è istantaneo**: si ri-avvolge solo la MFK (poche decine
  di byte), senza ricomprimere né ricifrare i dati.
- **Più chiavi d'accesso**: fino a 8 slot (password/keyfile diversi) aprono lo
  stesso archivio (utile per una password di riserva).

---

## 1. Primitive crittografiche

| Ruolo                         | Algoritmo                       |
|-------------------------------|---------------------------------|
| Derivazione KEK da password   | Argon2id                        |
| Combinazione con keyfile      | BLAKE3 keyed-hash               |
| Derivazione sottochiavi dati  | BLAKE3 derive_key (KDF)         |
| Cifratura autenticata (AEAD)  | XChaCha20-Poly1305 (nonce 24 B) |
| Hash per deduplicazione       | BLAKE3-256                      |
| MAC lista keyslot             | BLAKE3 keyed-hash (chiave MFK)  |
| Firma archivio                | Ed25519                         |
| Compressione                  | zstd                            |

---

## 2. Gerarchia delle chiavi

```
Chiave master dati (MFK)  ──► casuale, 32 byte, generata una volta
        │
        ├─ data_key  = derive_key("axcrypt v3 data key",  MFK)   cifra i blocchi
        └─ index_key = derive_key("axcrypt v3 index key", MFK)   cifra l'indice

Per ogni keyslot i:
   password ─► Argon2id(salt_i, params_i) ─► pw_key
                                               │  + keyfile (keyed_hash)
                                               ▼
                                     KEK_i (key-encryption-key)
   wrapped_i = XChaCha20Poly1305.encrypt(KEK_i, nonce_i, aad = core header, MFK)
```

Aprire = provare gli slot con (password+keyfile) finché uno decifra la MFK.

La **chiave di firma** Ed25519 è un'identità separata (`axcrypt keygen`),
conservata dall'utente. La sua pubkey sta nell'header; la privata firma.

---

## 3. Layout del file

```
┌──────────────────────────────────────────────────────────────┐
│ MAGIC (8) + u32 len + CoreHeader (immutabile, AAD, firmato)   │
├──────────────────────────────────────────────────────────────┤
│ Regione Keyslot (dimensione fissa, RISCRIVIBILE, non firmata) │
├──────────────────────────────────────────────────────────────┤
│ Chunk Stream       (ChunkRecord cifrati con data_key)         │
├──────────────────────────────────────────────────────────────┤
│ Encrypted Index    (catalogo file, cifrato con index_key)     │
├──────────────────────────────────────────────────────────────┤
│ Footer             (offset e conteggi, in chiaro)             │
├──────────────────────────────────────────────────────────────┤
│ Signature          (Ed25519, 64 B)                            │
└──────────────────────────────────────────────────────────────┘
```

### 3.0 Codifica binaria

Interi little-endian; array a taglia fissa scritti grezzi; sequenze e stringhe
(UTF-8) precedute dalla lunghezza: **`u32` in v4**, `u64` in v3 (il layout v3 è
quello che produceva bincode 1.x, ora decodificato a mano). Il decoder rifiuta
lunghezze che superano i byte rimasti, dati troncati e byte in eccesso.

### 3.1 CoreHeader (immutabile)

`format_version(u16)`, `flags(u32)`, `aead/compress/kdf algo (u8)`,
`cdc_min/avg/max (u32)`, `signer_pubkey[32]`, `archive_id[16]`,
`slot_region_start(u64)`, `slot_region_len(u64)`.

Tutti i campi sono a dimensione fissa: il corpo è sempre di **85 byte** (v3 e
v4), quindi `slot_region_start = 8 + 4 + 85 = 97` senza dipendenze circolari.
Il corpo serializzato è l'**AAD** per dati, indice e wrapping degli slot.

In lettura (prima ancora di verificare la firma) si rifiutano: magic
sconosciuto, `u32 len` diverso da 85, `format_version` incoerente col magic,
algoritmi sconosciuti, `slot_region_start`/`slot_region_len` diversi dai valori
fissi.

### 3.2 Regione Keyslot (dimensione fissa, riscrivibile)

`MAX_SLOTS = 8` slot riservati + MAC finale (32 B). Ogni slot (99 B):

| Campo          | Tipo        |
|----------------|-------------|
| `used`         | `u8`        |
| `argon_mem_kib`| `u32`       |
| `argon_iters`  | `u32`       |
| `argon_lanes`  | `u8`        |
| `flags`        | `u8` (bit0 = keyfile richiesto) |
| `salt`         | `[u8;16]`   |
| `nonce`        | `[u8;24]`   |
| `wrapped`      | `[u8;48]`   (MFK 32 + tag 16) |

I parametri Argon2id sono in chiaro e non autenticabili prima del KDF, quindi
hanno limiti massimi: `argon_mem_kib ≤ 4 GiB`, `1 ≤ argon_iters ≤ 32`,
`1 ≤ argon_lanes ≤ 16`. Uno slot fuori limite (danneggiato) viene saltato:
un bit alterato non può chiedere decine di GiB di RAM o ore di calcolo.

`MAC = BLAKE3::keyed_hash(MFK, byte_di_tutti_gli_slot)`: una volta recuperata la
MFK da uno slot valido, il MAC rileva manomissioni della lista d'accesso.

Essendo a dimensione fissa e subito dopo l'header, la regione si **riscrive sul
posto** (cambia password / aggiungi / togli chiave) senza spostare i dati.

### 3.3 ChunkRecord

```
[ nonce(24) ][ ct_len(u32) ][ ciphertext (tag incluso) ]
```
`ciphertext = XChaCha20Poly1305.encrypt(data_key, nonce, aad = core||archive_id||index, [flag||payload])`
con `flag` 0x01 = zstd, 0x00 = grezzo (blocchi incomprimibili). Blocchi
deduplicati per BLAKE3: un blocco uguale è memorizzato una sola volta.

### 3.4 Encrypted Index

Record come i blocchi: `[nonce(24)][ct_len(u32)][ciphertext]`, cifrato con
`index_key` (aad = core||"INDEX"). Nessun nome file è leggibile senza chiave.

Plaintext **v4** = `[flag] || payload` (flag 0x01 zstd, 0x00 grezzo) dove il
payload è:

```
u32 n_entries
  per ogni voce:
    u32 len + path (UTF-8)
    u64 size
    u32 mode
    u8  has_mtime  (0 | 1)
    [i64 mtime_secs, u32 mtime_nanos]   se has_mtime = 1
    u32 n_chunks + u64 chunk_id × n
    [u8;32] blake3 del file
u32 n_offsets + u64 chunk_offset × n
```

Plaintext **v3**: stessa struttura con lunghezze `u64`, senza `has_mtime`/mtime
e senza flag di compressione.

### 3.5 Footer

`chunk_count`, `chunk_stream_off`, `index_off`, `index_ct_len`,
`total_orig_size` (5 × `u64` = **40 byte**, v3 e v4), poi `u32 len` (deve
valere 40) e `FOOTER_MAGIC = "AXCF"`.

### 3.6 Signature

`Ed25519.sign(signer_privkey, BLAKE3(file SENZA la regione keyslot e SENZA la
firma))`. Firmare escludendo i keyslot fa sì che cambiare password o le chiavi
d'accesso **non invalidi la firma**: la firma autentica *i dati e la struttura*,
mentre ogni keyslot è autenticato per conto suo (AEAD) e la lista è coperta dal
MAC con la MFK. In verifica si può richiedere una `signer_pubkey` attesa
(`--trust`) per rifiutare archivi altrui.

---

## 4. Operazioni

- **PACK**: genera MFK e archive_id → scrive CoreHeader → crea slot 0 da
  (password+keyfile) → deriva data/index key → chunking (parallelo) → dedup →
  compressione+cifratura blocchi (parallelo) → indice cifrato → footer → firma.
- **UNPACK**: verifica firma (+trust) → apre uno slot → MFK → data/index key →
  legge footer → decifra blocchi → ricostruisce e verifica BLAKE3 di ogni file
  → scrive → ripristina la data di modifica (v4).
- **CHANGEPW / ADDKEY / RMKEY**: aprono uno slot per recuperare la MFK, poi
  riscrivono **solo** la regione keyslot sul posto. Nessuna ricifratura dei
  dati, firma intatta. Non si può rimuovere l'ultimo slot.

---

## 5. Note di sicurezza

- **Ordine comprimi-poi-cifra**: corretto; dati cifrati sono incomprimibili.
- **Attacco realistico**: non si rompe XChaCha20/Argon2id, si indovina la
  password. Difesa: Argon2id pesante (default ~1 GiB) + keyfile da 256 bit.
- **Firma vs keyslot**: la firma non copre i keyslot; un attaccante senza una
  chiave valida non può aggiungere uno slot (serve la MFK), e togliere/alterare
  slot è rilevato dal MAC all'apertura. Resta un possibile disturbo (DoS) sulla
  sola lista d'accesso: accettabile per uso personale, documentato.
- **Zeroize**: MFK, KEK, password e chiavi derivate vengono azzerate dopo l'uso.
- **Side-channel di compressione** (CRIME/BREACH): non si applica all'uso
  offline e non adattivo; nota da ricordare se un giorno si aggiunge una
  modalità di rete.

---

## 6. Streaming (v0.3)

Pack e unpack lavorano **a memoria limitata**: un blocco alla volta, chunking
incrementale (FastCDC StreamCDC) e accesso casuale ai blocchi tramite la tabella
`chunk_offsets` nell'indice. Il picco di RAM resta costante (decine di MB) a
prescindere dalla dimensione dell'archivio, quindi regge input più grandi della
memoria disponibile. Misurato: ~25 MB di picco sia con 200 MB sia con 1 GB di
input.

## 7. Test di robustezza

La suite del core verifica che **ogni** byte alterato (inizio e fine del file
più campioni casuali) e **ogni** troncamento producano un errore pulito, senza
panico né allocazioni eccessive, e che la fixture v3 reale
(`crates/core/tests/fixtures/`) continui ad aprirsi, estrarsi, cambiare password
e ripararsi con il suo `.rec`.
