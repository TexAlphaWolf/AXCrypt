//! Recovery record: parità Reed-Solomon in un file sidecar `.rec`.
//!
//! Idea (come i recovery record di RAR / PAR2): l'archivio viene diviso in
//! `data_count` blocchi; si calcolano `parity_count` blocchi di parità e, per
//! ogni blocco, un hash breve. Se alcuni blocchi dell'archivio si danneggiano,
//! `repair` li individua confrontando gli hash (trattandoli come "cancellati")
//! e li ricostruisce dalla parità, finché i blocchi corrotti sono ≤ parità.
//!
//! Il file `.rec` è separato: l'archivio resta intatto (firma valida). Reed-
//! Solomon in GF(2^8): data+parità ≤ 255 blocchi totali.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

use crate::error::{AxError, Result};

const REC_MAGIC: [u8; 8] = *b"AXCREC1\0";
const MAX_DATA: usize = 200; // lascia spazio alla parità entro i 255 totali

#[derive(Serialize, Deserialize)]
struct RecMeta {
    block_size: u32,
    data_count: u32,
    parity_count: u32,
    orig_len: u64,
    archive_hash: [u8; 32],
    data_hashes: Vec<[u8; 16]>,
    parity_hashes: Vec<[u8; 16]>,
}

/// Esito della creazione del recovery record.
pub struct RecoveryStats {
    pub data_count: usize,
    pub parity_count: usize,
    pub block_size: usize,
    pub overhead_bytes: u64,
}

/// Esito di una riparazione.
pub struct RepairReport {
    /// Numero di blocchi ricostruiti (0 = archivio già integro).
    pub repaired: usize,
    pub already_ok: bool,
    pub data_count: usize,
    pub parity_count: usize,
}

fn hash16(b: &[u8]) -> [u8; 16] {
    let h = blake3::hash(b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// Sceglie (data_count, parity_count, block_size) per una certa ridondanza %.
fn choose_params(len: usize, redundancy_pct: u32) -> Result<(usize, usize, usize)> {
    if redundancy_pct == 0 || redundancy_pct > 100 {
        return Err(AxError::RecoveryParams(
            "ridondanza deve essere tra 1 e 100".into(),
        ));
    }
    let len = len.max(1);
    let data_count = len.clamp(1, MAX_DATA);
    let block_size = len.div_ceil(data_count);
    let mut parity_count = (data_count * redundancy_pct as usize).div_ceil(100);
    parity_count = parity_count.max(1);
    if data_count + parity_count > 255 {
        parity_count = 255 - data_count;
    }
    Ok((data_count, parity_count, block_size))
}

/// Crea il file di recupero `.rec` per `archive`.
pub fn protect(archive: &Path, rec_out: &Path, redundancy_pct: u32) -> Result<RecoveryStats> {
    let mut data = fs::read(archive)?;
    let orig_len = data.len() as u64;
    let archive_hash = *blake3::hash(&data).as_bytes();

    let (data_count, parity_count, block_size) = choose_params(data.len(), redundancy_pct)?;
    data.resize(data_count * block_size, 0); // padding a multiplo di block_size

    let data_shards: Vec<&[u8]> = (0..data_count)
        .map(|i| &data[i * block_size..(i + 1) * block_size])
        .collect();
    let mut parity: Vec<Vec<u8>> = (0..parity_count).map(|_| vec![0u8; block_size]).collect();

    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| AxError::RecoveryParams(e.to_string()))?;
    rs.encode_sep(&data_shards, &mut parity)
        .map_err(|e| AxError::RecoveryParams(e.to_string()))?;

    let data_hashes: Vec<[u8; 16]> = data_shards.iter().map(|s| hash16(s)).collect();
    let parity_hashes: Vec<[u8; 16]> = parity.iter().map(|p| hash16(p)).collect();

    let meta = RecMeta {
        block_size: block_size as u32,
        data_count: data_count as u32,
        parity_count: parity_count as u32,
        orig_len,
        archive_hash,
        data_hashes,
        parity_hashes,
    };

    let mut f = BufWriter::new(File::create(rec_out)?);
    f.write_all(&REC_MAGIC)?;
    let mb = bincode::serialize(&meta)?;
    f.write_all(&(mb.len() as u32).to_le_bytes())?;
    f.write_all(&mb)?;
    for p in &parity {
        f.write_all(p)?;
    }
    f.flush()?;

    Ok(RecoveryStats {
        data_count,
        parity_count,
        block_size,
        overhead_bytes: (parity_count * block_size) as u64,
    })
}

fn read_rec(path: &Path) -> Result<(RecMeta, Vec<u8>)> {
    let buf = fs::read(path)?;
    if buf.len() < 12 || buf[..8] != REC_MAGIC {
        return Err(AxError::RecoveryBadMagic);
    }
    let mlen = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    if buf.len() < 12 + mlen {
        return Err(AxError::RecoveryBadMagic);
    }
    let meta: RecMeta = bincode::deserialize(&buf[12..12 + mlen])?;
    let parity = buf[12 + mlen..].to_vec();
    let expect = meta.parity_count as usize * meta.block_size as usize;
    if parity.len() != expect {
        return Err(AxError::RecoveryBadMagic);
    }
    Ok((meta, parity))
}

/// Verifica/ripara `archive` usando il file `.rec`, scrivendo il risultato in
/// `out`. Se l'archivio è già integro, non scrive nulla e lo segnala.
pub fn repair(archive: &Path, rec: &Path, out: &Path) -> Result<RepairReport> {
    let (meta, parity_bytes) = read_rec(rec)?;
    let bs = meta.block_size as usize;
    let dc = meta.data_count as usize;
    let pc = meta.parity_count as usize;

    let mut data = fs::read(archive)?;
    data.resize(dc * bs, 0);

    // integrità rapida: se l'hash combacia, già a posto
    let trimmed_len = (meta.orig_len as usize).min(data.len());
    if *blake3::hash(&data[..trimmed_len]).as_bytes() == meta.archive_hash {
        return Ok(RepairReport {
            repaired: 0,
            already_ok: true,
            data_count: dc,
            parity_count: pc,
        });
    }

    // individua i blocchi corrotti (hash non combaciante) come "cancellati"
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(dc + pc);
    let mut corrupt = 0usize;
    for i in 0..dc {
        let blk = &data[i * bs..(i + 1) * bs];
        if hash16(blk) == meta.data_hashes[i] {
            shards.push(Some(blk.to_vec()));
        } else {
            shards.push(None);
            corrupt += 1;
        }
    }
    for j in 0..pc {
        let blk = &parity_bytes[j * bs..(j + 1) * bs];
        if hash16(blk) == meta.parity_hashes[j] {
            shards.push(Some(blk.to_vec()));
        } else {
            shards.push(None);
            corrupt += 1;
        }
    }

    if corrupt > pc {
        return Err(AxError::RecoveryTooDamaged {
            corrupt,
            parity: pc,
        });
    }

    let rs = ReedSolomon::new(dc, pc).map_err(|e| AxError::RecoveryParams(e.to_string()))?;
    rs.reconstruct(&mut shards)
        .map_err(|e| AxError::RecoveryParams(e.to_string()))?;

    let mut repaired = Vec::with_capacity(dc * bs);
    for shard in shards.iter().take(dc) {
        repaired.extend_from_slice(shard.as_ref().ok_or(AxError::RecoveryMismatch)?);
    }
    repaired.truncate(meta.orig_len as usize);

    if *blake3::hash(&repaired).as_bytes() != meta.archive_hash {
        return Err(AxError::RecoveryMismatch);
    }
    fs::write(out, &repaired)?;

    Ok(RepairReport {
        repaired: corrupt,
        already_ok: false,
        data_count: dc,
        parity_count: pc,
    })
}
