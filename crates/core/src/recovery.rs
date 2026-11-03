//! Recovery record: parità Reed-Solomon in un file sidecar `.rec`.
//!
//! Idea (come i recovery record di RAR / PAR2): l'archivio viene diviso in
//! `data_count` blocchi; si calcolano `parity_count` blocchi di parità e, per
//! ogni blocco, un hash breve. Se alcuni blocchi dell'archivio si danneggiano,
//! `repair` li individua confrontando gli hash (trattandoli come "cancellati")
//! e li ricostruisce dalla parità, finché i blocchi dati danneggiati sono al
//! massimo quanti i blocchi di parità rimasti integri.
//!
//! Il file `.rec` è separato: l'archivio resta intatto (firma valida).
//! Libreria: `reed-solomon-simd` (codifica Reed-Solomon in GF(2^16), O(n log n)).
//! Formato `.rec` v2: i `.rec` v1 (vecchia libreria) vanno rigenerati con
//! `protect`.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{AxError, Result};

const REC_MAGIC: [u8; 8] = *b"AXCREC2\0";
/// Numero massimo di blocchi dati: più blocchi = danni sparsi più economici
/// da riparare (ogni blocco danneggiato consuma un blocco di parità).
const MAX_DATA: usize = 1024;

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
    /// Numero di blocchi dati ricostruiti (0 = archivio già integro).
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

fn rs_err(e: impl std::fmt::Display) -> AxError {
    AxError::RecoveryParams(e.to_string())
}

/// Sceglie (data_count, parity_count, block_size) per una certa ridondanza %.
/// La dimensione dei blocchi è pari (vincolo della libreria Reed-Solomon).
fn choose_params(len: usize, redundancy_pct: u32) -> Result<(usize, usize, usize)> {
    if redundancy_pct == 0 || redundancy_pct > 100 {
        return Err(AxError::RecoveryParams(
            "ridondanza deve essere tra 1 e 100".into(),
        ));
    }
    let len = len.max(1);
    let data_count = len.clamp(1, MAX_DATA);
    let block_size = len.div_ceil(data_count).next_multiple_of(2).max(2);
    let parity_count = (data_count * redundancy_pct as usize).div_ceil(100).max(1);
    Ok((data_count, parity_count, block_size))
}

/// Crea il file di recupero `.rec` per `archive`.
pub fn protect(archive: &Path, rec_out: &Path, redundancy_pct: u32) -> Result<RecoveryStats> {
    let mut data = fs::read(archive)?;
    let orig_len = data.len() as u64;
    let archive_hash = *blake3::hash(&data).as_bytes();

    let (data_count, parity_count, block_size) = choose_params(data.len(), redundancy_pct)?;
    data.resize(data_count * block_size, 0); // padding a multiplo di block_size

    let parity = reed_solomon_simd::encode(data_count, parity_count, data.chunks(block_size))
        .map_err(rs_err)?;

    let data_hashes: Vec<[u8; 16]> = data.chunks(block_size).map(hash16).collect();
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
    let bs = meta.block_size as usize;
    let consistent = bs >= 2
        && bs.is_multiple_of(2)
        && meta.data_hashes.len() == meta.data_count as usize
        && meta.parity_hashes.len() == meta.parity_count as usize;
    let parity = buf[12 + mlen..].to_vec();
    if !consistent || parity.len() != meta.parity_count as usize * bs {
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

    // blocchi dati integri / danneggiati (hash non combaciante = "cancellato")
    let mut originals: Vec<(usize, &[u8])> = Vec::with_capacity(dc);
    let mut damaged: Vec<usize> = Vec::new();
    for (i, (blk, h)) in data.chunks(bs).zip(&meta.data_hashes).enumerate() {
        if hash16(blk) == *h {
            originals.push((i, blk));
        } else {
            damaged.push(i);
        }
    }
    // blocchi di parità integri
    let recovery: Vec<(usize, &[u8])> = parity_bytes
        .chunks(bs)
        .zip(&meta.parity_hashes)
        .enumerate()
        .filter(|(_, (blk, h))| hash16(blk) == **h)
        .map(|(j, (blk, _))| (j, blk))
        .collect();

    if damaged.is_empty() {
        // tutti i blocchi combaciano ma l'hash globale no: .rec di un altro archivio
        return Err(AxError::RecoveryMismatch);
    }
    if damaged.len() > recovery.len() {
        return Err(AxError::RecoveryTooDamaged {
            corrupt: damaged.len() + (pc - recovery.len()),
            parity: pc,
        });
    }

    let restored = reed_solomon_simd::decode(dc, pc, originals, recovery).map_err(rs_err)?;
    for &i in &damaged {
        let shard = restored.get(&i).ok_or(AxError::RecoveryMismatch)?;
        data[i * bs..(i + 1) * bs].copy_from_slice(shard);
    }
    data.truncate(meta.orig_len as usize);

    if *blake3::hash(&data).as_bytes() != meta.archive_hash {
        return Err(AxError::RecoveryMismatch);
    }
    fs::write(out, &data)?;

    Ok(RepairReport {
        repaired: damaged.len(),
        already_ok: false,
        data_count: dc,
        parity_count: pc,
    })
}
