//! Costanti del formato v2, header "core" (immutabile), footer e indice.
//!
//! Novità v2: cifratura a busta. Una chiave master casuale (MFK) cifra i dati;
//! la MFK è avvolta in una **regione keyslot** riscrivibile (vedi `keyslot.rs`).
//! Così cambiare password/keyfile non richiede di ricifrare i dati. Vedi
//! `docs/FORMAT_SPEC.md`.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::error::{AxError, Result};

/// Magic iniziale del file.
pub const MAGIC: [u8; 8] = *b"AXCRYPT3";
/// Versione del formato serializzato.
pub const FORMAT_VERSION: u16 = 3;
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
/// Tutti i campi sono a dimensione fissa: la lunghezza serializzata è costante,
/// così `slot_region_start` si può fissare senza dipendenze circolari.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl CoreHeader {
    /// Byte del corpo (senza magic), usati come AAD.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    /// Lunghezza fissa del corpo serializzato (campi tutti a taglia fissa).
    pub fn body_len() -> usize {
        let dummy = CoreHeader {
            format_version: 0,
            flags: 0,
            aead_algo: 0,
            compress_algo: 0,
            kdf_algo: 0,
            cdc_min: 0,
            cdc_avg: 0,
            cdc_max: 0,
            signer_pubkey: [0; 32],
            archive_id: [0; 16],
            slot_region_start: 0,
            slot_region_len: 0,
        };
        bincode::serialize(&dummy).unwrap().len()
    }

    /// Offset a cui inizia la regione keyslot: `8 (magic) + 4 (len) + body`.
    pub fn slot_region_start_for_body_len(body_len: usize) -> u64 {
        (8 + 4 + body_len) as u64
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<Vec<u8>> {
        let body = self.body_bytes()?;
        w.write_all(&MAGIC)?;
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(&body)?;
        Ok(body)
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<(CoreHeader, Vec<u8>)> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(AxError::BadMagic);
        }
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        let header: CoreHeader = bincode::deserialize(&body)?;
        if header.format_version != FORMAT_VERSION {
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
        Ok((header, body))
    }
}

/// Footer con gli offset necessari a ritrovare indice e stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Footer {
    pub chunk_count: u64,
    pub chunk_stream_off: u64,
    pub index_off: u64,
    pub index_ct_len: u64,
    pub total_orig_size: u64,
}

impl Footer {
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        let body = bincode::serialize(self)?;
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
        if n < 8 + len {
            return Err(AxError::Corrupt("footer troncato"));
        }
        let body = &buf_without_sig[n - 8 - len..n - 8];
        Ok(bincode::deserialize(body)?)
    }
}

/// Indice (catalogo) dei file, serializzato e poi cifrato.
///
/// `chunk_offsets[i]` = offset nel file del record del blocco `i` (inizio del
/// nonce). Serve per l'accesso casuale ai blocchi in fase di estrazione a
/// streaming (memoria limitata).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexPlaintext {
    pub entries: Vec<FileEntry>,
    pub chunk_offsets: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub chunks: Vec<u64>,
    pub blake3: [u8; 32],
}
