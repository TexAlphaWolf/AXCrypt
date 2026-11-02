//! Compressione dei blocchi con zstd e fallback "grezzo" per dati
//! incomprimibili (già compressi/cifrati): così un blocco non viene mai
//! gonfiato.

use std::io::Cursor;

use crate::error::Result;

/// Flag che precede il payload compresso di un blocco.
pub const RAW: u8 = 0x00;
pub const ZSTD: u8 = 0x01;

/// Livello di compressione zstd di default (buon compromesso).
pub const DEFAULT_LEVEL: i32 = 9;

/// Comprime un blocco. Restituisce `[flag] || payload`, scegliendo RAW se la
/// compressione non riduce la dimensione.
pub fn compress_block(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let compressed = zstd::encode_all(Cursor::new(data), level)?;
    if compressed.len() + 1 < data.len() {
        let mut out = Vec::with_capacity(compressed.len() + 1);
        out.push(ZSTD);
        out.extend_from_slice(&compressed);
        Ok(out)
    } else {
        let mut out = Vec::with_capacity(data.len() + 1);
        out.push(RAW);
        out.extend_from_slice(data);
        Ok(out)
    }
}

/// Inverte `compress_block`: legge il flag e decomprime se necessario.
pub fn decompress_block(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    let (flag, payload) = (blob[0], &blob[1..]);
    match flag {
        ZSTD => Ok(zstd::decode_all(Cursor::new(payload))?),
        _ => Ok(payload.to_vec()), // RAW o sconosciuto trattato come grezzo
    }
}
