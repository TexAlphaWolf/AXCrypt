//! Suddivisione in blocchi content-defined (FastCDC) e deduplicazione.
//!
//! FastCDC trova confini di blocco in base al contenuto: inserire o togliere
//! byte all'inizio di un file sposta pochi confini invece di tutti, così i
//! blocchi uguali restano identici tra versioni diverse e la dedup funziona.

use std::collections::HashMap;

use fastcdc::v2020::FastCDC;

/// Un blocco individuato nel file: intervallo e hash BLAKE3.
pub struct Chunk {
    pub offset: usize,
    pub length: usize,
    pub hash: [u8; 32],
}

/// Spezza `data` in blocchi secondo i parametri FastCDC.
pub fn split(data: &[u8], min: u32, avg: u32, max: u32) -> Vec<Chunk> {
    let mut out = Vec::new();
    for c in FastCDC::new(data, min, avg, max) {
        let slice = &data[c.offset..c.offset + c.length];
        let hash = blake3::hash(slice);
        out.push(Chunk {
            offset: c.offset,
            length: c.length,
            hash: *hash.as_bytes(),
        });
    }
    out
}

/// Mappa di deduplicazione: hash del blocco → indice nel chunk stream.
#[derive(Default)]
pub struct Deduper {
    map: HashMap<[u8; 32], u64>,
    next_index: u64,
}

impl Deduper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restituisce `(index, is_new)`. Se il blocco è già noto, `is_new` è false
    /// e l'indice è quello esistente (non va riscritto).
    pub fn get_or_insert(&mut self, hash: &[u8; 32]) -> (u64, bool) {
        if let Some(&idx) = self.map.get(hash) {
            (idx, false)
        } else {
            let idx = self.next_index;
            self.map.insert(*hash, idx);
            self.next_index += 1;
            (idx, true)
        }
    }

    pub fn unique_count(&self) -> u64 {
        self.next_index
    }
}
