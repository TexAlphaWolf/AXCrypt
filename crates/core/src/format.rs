//! Costanti del formato, header "core" (immutabile), footer e indice.
//!
//! Cifratura a busta: una chiave master casuale (MFK) cifra i dati; la MFK è
//! avvolta in una **regione keyslot** riscrivibile (vedi `keyslot.rs`), così
//! cambiare password/keyfile non richiede di ricifrare i dati.
//!
//! Versioni: si scrive sempre la **v4**; la **v3** resta leggibile (e le
//! operazioni sulle chiavi funzionano anche su archivi v3). La codifica è in
//! `codec.rs`. Vedi `docs/FORMAT_SPEC.md`.

use std::io::{Read, Write};

use crate::codec::{Dec, Enc, LenWidth};
use crate::compress;
use crate::error::{AxError, Result};
use crate::keyslot::SLOT_REGION_LEN;

/// Magic iniziale del formato corrente (v4).
pub const MAGIC: [u8; 8] = *b"AXCRYPT4";
/// Magic del formato v3 (solo lettura).
pub const MAGIC_V3: [u8; 8] = *b"AXCRYPT3";
/// Versione del formato che viene scritta.
pub const FORMAT_VERSION: u16 = 4;
/// Versione precedente, ancora leggibile.
pub const FORMAT_V3: u16 = 3;
/// Lunghezza fissa del corpo dell'header (uguale in v3 e v4).
pub const HEADER_BODY_LEN: usize = 85;
/// Lunghezza fissa del corpo del footer (uguale in v3 e v4).
pub const FOOTER_BODY_LEN: usize = 40;
/// Magic del footer.
pub const FOOTER_MAGIC: [u8; 4] = *b"AXCF";

pub const AEAD_XCHACHA20POLY1305: u8 = 1;
pub const COMPRESS_ZSTD: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;

pub mod flags {
    /// Almeno uno slot richiede un keyfile.
    pub const KEYFILE_REQUIRED: u32 = 1 << 0;
    pub const SIGNED: u32 = 1 << 1;
}

/// Parametri di chunking (FastCDC), in byte.
pub const CDC_MIN: u32 = 16 * 1024;
pub const CDC_AVG: u32 = 64 * 1024;
pub const CDC_MAX: u32 = 256 * 1024;

/// Parametri Argon2id di default.
pub const ARGON_MEM_KIB: u32 = 1_048_576; // 1 GiB
pub const ARGON_ITERS: u32 = 3;
pub const ARGON_LANES: u8 = 4;

/// Limiti massimi accettati per i parametri Argon2id di uno slot.
///
/// I parametri sono scritti in chiaro nello slot e non si possono autenticare
/// prima di aver eseguito il KDF: senza limiti, un bit alterato (danno o
/// manomissione) potrebbe chiedere decine di GiB di RAM o miliardi di
/// iterazioni. Ampiamente sopra il profilo `strong` (1 GiB, 3 iter, 4 lane).
pub const MAX_ARGON_MEM_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
pub const MAX_ARGON_ITERS: u32 = 32;
pub const MAX_ARGON_LANES: u8 = 16;

/// `true` se i parametri sono dentro i limiti accettati.
pub fn argon_params_ok(mem_kib: u32, iters: u32, lanes: u8) -> bool {
    mem_kib <= MAX_ARGON_MEM_KIB
        && (1..=MAX_ARGON_ITERS).contains(&iters)
        && (1..=MAX_ARGON_LANES).contains(&lanes)
}

/// Parametri Argon2id usati per avvolgere la MFK in uno slot.
#[derive(Clone, Copy, Debug)]
pub struct ArgonParams {
    pub mem_kib: u32,
    pub iters: u32,
    pub lanes: u8,
}

impl ArgonParams {
    /// Impostazione pesante consigliata per l'uso reale (~1 GiB).
    pub fn strong() -> Self {
        ArgonParams {
            mem_kib: ARGON_MEM_KIB,
            iters: ARGON_ITERS,
            lanes: ARGON_LANES,
        }
    }

    /// Impostazione leggera per test/debug (NON per uso reale).
    pub fn fast() -> Self {
        ArgonParams {
            mem_kib: 8 * 1024,
            iters: 1,
            lanes: 1,
        }
    }
}

/// Header "core": immutabile dopo la creazione. È l'AAD dei dati ed è coperto
/// dalla firma. NON contiene la regione keyslot (quella è riscrivibile).
///
/// Tutti i campi sono a dimensione fissa ([`HEADER_BODY_LEN`] byte), così
/// `slot_region_start` si può fissare senza dipendenze circolari.
#[derive(Debug, Clone)]
pub struct CoreHeader {
    pub format_version: u16,
    pub flags: u32,
    pub aead_algo: u8,
    pub compress_algo: u8,
    pub kdf_algo: u8,
    pub cdc_min: u32,
    pub cdc_avg: u32,
    pub cdc_max: u32,
    pub signer_pubkey: [u8; 32],
    pub archive_id: [u8; 16],
    pub slot_region_start: u64,
    pub slot_region_len: u64,
}

fn magic_for(version: u16) -> Result<[u8; 8]> {
    match version {
        FORMAT_VERSION => Ok(MAGIC),
        FORMAT_V3 => Ok(MAGIC_V3),
        _ => Err(AxError::BadMagic),
    }
}

impl CoreHeader {
    /// Byte del corpo (senza magic), usati come AAD.
    pub fn body_bytes(&self) -> Vec<u8> {
        // Solo campi a taglia fissa: la larghezza delle lunghezze è irrilevante.
        let mut e = Enc::new(LenWidth::U32);
        e.u16(self.format_version);
        e.u32(self.flags);
        e.u8(self.aead_algo);
        e.u8(self.compress_algo);
        e.u8(self.kdf_algo);
        e.u32(self.cdc_min);
        e.u32(self.cdc_avg);
        e.u32(self.cdc_max);
        e.raw(&self.signer_pubkey);
        e.raw(&self.archive_id);
        e.u64(self.slot_region_start);
        e.u64(self.slot_region_len);
        let b = e.finish();
        debug_assert_eq!(b.len(), HEADER_BODY_LEN);
        b
    }

    fn decode(body: &[u8]) -> Result<CoreHeader> {
        let mut d = Dec::new(body, LenWidth::U32);
        let h = CoreHeader {
            format_version: d.u16()?,
            flags: d.u32()?,
            aead_algo: d.u8()?,
            compress_algo: d.u8()?,
            kdf_algo: d.u8()?,
            cdc_min: d.u32()?,
            cdc_avg: d.u32()?,
            cdc_max: d.u32()?,
            signer_pubkey: d.array()?,
            archive_id: d.array()?,
            slot_region_start: d.u64()?,
            slot_region_len: d.u64()?,
        };
        d.finish()?;
        Ok(h)
    }

    /// Lunghezza fissa del corpo serializzato.
    pub fn body_len() -> usize {
        HEADER_BODY_LEN
    }

    /// Offset a cui inizia la regione keyslot: `8 (magic) + 4 (len) + body`.
    pub fn slot_region_start_for_body_len(body_len: usize) -> u64 {
        (8 + 4 + body_len) as u64
    }

    /// Larghezza delle lunghezze usata dall'indice di questa versione.
    pub fn len_width(&self) -> LenWidth {
        if self.format_version >= FORMAT_VERSION {
            LenWidth::U32
        } else {
            LenWidth::U64
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<Vec<u8>> {
        let body = self.body_bytes();
        w.write_all(&magic_for(self.format_version)?)?;
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(&body)?;
        Ok(body)
    }

    /// Legge e valida l'header (v4 o v3). Restituisce anche i byte del corpo
    /// così come sono su disco (servono come AAD).
    pub fn read_from<R: Read>(r: &mut R) -> Result<(CoreHeader, Vec<u8>)> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        let version = if magic == MAGIC {
            FORMAT_VERSION
        } else if magic == MAGIC_V3 {
            FORMAT_V3
        } else {
            return Err(AxError::BadMagic);
        };
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        // Taglia fissa: niente allocazioni decise da un header non ancora
        // verificato.
        if u32::from_le_bytes(len_buf) as usize != HEADER_BODY_LEN {
            return Err(AxError::Corrupt("lunghezza dell'header non valida"));
        }
        let mut body = vec![0u8; HEADER_BODY_LEN];
        r.read_exact(&mut body)?;
        let header = CoreHeader::decode(&body)?;
        if header.format_version != version {
            return Err(AxError::BadMagic);
        }
        if header.aead_algo != AEAD_XCHACHA20POLY1305 {
            return Err(AxError::UnsupportedAlgo("aead"));
        }
        if header.compress_algo != COMPRESS_ZSTD {
            return Err(AxError::UnsupportedAlgo("compress"));
        }
        if header.kdf_algo != KDF_ARGON2ID {
            return Err(AxError::UnsupportedAlgo("kdf"));
        }
        if header.slot_region_start != Self::slot_region_start_for_body_len(HEADER_BODY_LEN)
            || header.slot_region_len != SLOT_REGION_LEN as u64
        {
            return Err(AxError::Corrupt("regione keyslot non valida"));
        }
        Ok((header, body))
    }
}

/// Footer con gli offset necessari a ritrovare indice e stream.
#[derive(Debug, Clone)]
pub struct Footer {
    pub chunk_count: u64,
    pub chunk_stream_off: u64,
    pub index_off: u64,
    pub index_ct_len: u64,
    pub total_orig_size: u64,
}

impl Footer {
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new(LenWidth::U32);
        e.u64(self.chunk_count);
        e.u64(self.chunk_stream_off);
        e.u64(self.index_off);
        e.u64(self.index_ct_len);
        e.u64(self.total_orig_size);
        e.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Footer> {
        if body.len() != FOOTER_BODY_LEN {
            return Err(AxError::Corrupt("lunghezza del footer non valida"));
        }
        let mut d = Dec::new(body, LenWidth::U32);
        let f = Footer {
            chunk_count: d.u64()?,
            chunk_stream_off: d.u64()?,
            index_off: d.u64()?,
            index_ct_len: d.u64()?,
            total_orig_size: d.u64()?,
        };
        d.finish()?;
        Ok(f)
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        let body = self.body_bytes();
        w.write_all(&body)?;
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(&FOOTER_MAGIC)?;
        Ok(())
    }

    /// Legge il footer dalla coda del file (già privato della firma).
    pub fn read_tail(buf_without_sig: &[u8]) -> Result<Footer> {
        let n = buf_without_sig.len();
        if n < 8 {
            return Err(AxError::Corrupt("file troppo corto per il footer"));
        }
        if buf_without_sig[n - 4..n] != FOOTER_MAGIC {
            return Err(AxError::Corrupt("footer magic assente"));
        }
        let len = u32::from_le_bytes(buf_without_sig[n - 8..n - 4].try_into().unwrap()) as usize;
        if len != FOOTER_BODY_LEN || n < 8 + len {
            return Err(AxError::Corrupt("footer troncato o non valido"));
        }
        Footer::decode(&buf_without_sig[n - 8 - len..n - 8])
    }
}

/// Data di modifica di un file: secondi (anche negativi, prima del 1970) e
/// nanosecondi rispetto all'epoca Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTime {
    pub secs: i64,
    pub nanos: u32,
}

impl FileTime {
    pub fn from_system(t: std::time::SystemTime) -> Option<FileTime> {
        use std::time::UNIX_EPOCH;
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Some(FileTime {
                secs: i64::try_from(d.as_secs()).ok()?,
                nanos: d.subsec_nanos(),
            }),
            Err(e) => {
                // prima del 1970: normalizza a nanos positivi
                let d = e.duration();
                let mut secs = -i64::try_from(d.as_secs()).ok()?;
                let mut nanos = d.subsec_nanos();
                if nanos > 0 {
                    secs -= 1;
                    nanos = 1_000_000_000 - nanos;
                }
                Some(FileTime { secs, nanos })
            }
        }
    }

    pub fn to_system(self) -> Option<std::time::SystemTime> {
        use std::time::{Duration, UNIX_EPOCH};
        if self.nanos >= 1_000_000_000 {
            return None;
        }
        if self.secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(self.secs as u64, self.nanos))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(self.secs.unsigned_abs()))?
                .checked_add(Duration::from_nanos(self.nanos as u64))
        }
    }
}

/// Indice (catalogo) dei file, serializzato e poi cifrato.
///
/// `chunk_offsets[i]` = offset nel file del record del blocco `i` (inizio del
/// nonce). Serve per l'accesso casuale ai blocchi in fase di estrazione a
/// streaming (memoria limitata).
#[derive(Debug, Clone, Default)]
pub struct IndexPlaintext {
    pub entries: Vec<FileEntry>,
    pub chunk_offsets: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    /// Data di modifica (solo v4; `None` negli archivi v3).
    pub mtime: Option<FileTime>,
    pub chunks: Vec<u64>,
    pub blake3: [u8; 32],
}

/// Byte minimi di una voce nell'indice (per i controlli anti-allocazione).
const MIN_ENTRY_V4: usize = 4 + 8 + 4 + 1 + 4 + 32;
const MIN_ENTRY_V3: usize = 8 + 8 + 4 + 8 + 32;

impl IndexPlaintext {
    /// Codifica v4: struttura con lunghezze `u32`, poi compressa (zstd con
    /// fallback grezzo, come i blocchi) prima di essere cifrata.
    pub fn encode_v4(&self, zstd_level: i32) -> Result<Vec<u8>> {
        let mut e = Enc::new(LenWidth::U32);
        e.len(self.entries.len())?;
        for f in &self.entries {
            e.str(&f.path)?;
            e.u64(f.size);
            e.u32(f.mode);
            match f.mtime {
                Some(t) => {
                    e.u8(1);
                    e.i64(t.secs);
                    e.u32(t.nanos);
                }
                None => e.u8(0),
            }
            e.len(f.chunks.len())?;
            for &c in &f.chunks {
                e.u64(c);
            }
            e.raw(&f.blake3);
        }
        e.len(self.chunk_offsets.len())?;
        for &o in &self.chunk_offsets {
            e.u64(o);
        }
        compress::compress_block(&e.finish(), zstd_level)
    }

    /// Decodifica l'indice (già decifrato) secondo la versione dell'archivio.
    pub fn decode(bytes: &[u8], version: u16) -> Result<IndexPlaintext> {
        if version >= FORMAT_VERSION {
            let plain = compress::decompress_block(bytes)?;
            Self::decode_v4(&plain)
        } else {
            Self::decode_v3(bytes)
        }
    }

    fn decode_v4(b: &[u8]) -> Result<IndexPlaintext> {
        let mut d = Dec::new(b, LenWidth::U32);
        let n = d.len(MIN_ENTRY_V4)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let path = d.string()?;
            let size = d.u64()?;
            let mode = d.u32()?;
            let mtime = match d.u8()? {
                0 => None,
                1 => Some(FileTime {
                    secs: d.i64()?,
                    nanos: d.u32()?,
                }),
                _ => return Err(AxError::Decode("campo data non valido")),
            };
            let chunks = d.u64_vec()?;
            let blake3 = d.array()?;
            entries.push(FileEntry {
                path,
                size,
                mode,
                mtime,
                chunks,
                blake3,
            });
        }
        let chunk_offsets = d.u64_vec()?;
        d.finish()?;
        Ok(IndexPlaintext {
            entries,
            chunk_offsets,
        })
    }

    /// Layout v3 (identico a bincode 1.x): lunghezze `u64`, niente mtime,
    /// niente compressione.
    fn decode_v3(b: &[u8]) -> Result<IndexPlaintext> {
        let mut d = Dec::new(b, LenWidth::U64);
        let n = d.len(MIN_ENTRY_V3)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let path = d.string()?;
            let size = d.u64()?;
            let mode = d.u32()?;
            let chunks = d.u64_vec()?;
            let blake3 = d.array()?;
            entries.push(FileEntry {
                path,
                size,
                mode,
                mtime: None,
                chunks,
                blake3,
            });
        }
        let chunk_offsets = d.u64_vec()?;
        d.finish()?;
        Ok(IndexPlaintext {
            entries,
            chunk_offsets,
        })
    }
}
