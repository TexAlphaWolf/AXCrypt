//! Orchestrazione del formato v2 in modalità **streaming**: pack/unpack
//! lavorano a memoria limitata (un blocco alla volta), così reggono archivi
//! più grandi della RAM. Chunking incrementale (FastCDC StreamCDC) e accesso
//! casuale ai blocchi tramite la tabella offset nell'indice.
//!
//! Compressione/cifratura dei blocchi in parallelo (rayon) a lotti.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use fastcdc::v2020::StreamCDC;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

use crate::compress;
use crate::crypto::{self, NONCE_LEN};
use crate::error::{AxError, Result};
use crate::format::{self, ArgonParams, CoreHeader, FileEntry, Footer, IndexPlaintext};
use crate::keys::{self, DerivedKeys, Secret};
use crate::keyslot::{self, KeySlot, MAX_SLOTS, SLOT_REGION_LEN};

/// File da inserire nell'archivio.
pub struct InputFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub mode: u32,
}

/// Statistiche di un'operazione di pack.
pub struct PackStats {
    pub orig_size: u64,
    pub archive_size: u64,
    pub chunk_count: u64,
}

fn aad_chunk(core_body: &[u8], archive_id: &[u8; 16], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(core_body.len() + 16 + 8);
    aad.extend_from_slice(core_body);
    aad.extend_from_slice(archive_id);
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

fn aad_index(core_body: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(core_body.len() + 5);
    aad.extend_from_slice(core_body);
    aad.extend_from_slice(b"INDEX");
    aad
}

// =====================================================================
// Scrittura: contesto che conta gli offset e aggiorna il digest firmato.
// La regione keyslot NON entra nel digest (resta modificabile).
// =====================================================================

struct OutCtx {
    w: BufWriter<File>,
    hasher: blake3::Hasher,
    offset: u64,
}

impl OutCtx {
    fn plain(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b)?;
        self.offset += b.len() as u64;
        Ok(())
    }
    fn hashed(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b)?;
        self.hasher.update(b);
        self.offset += b.len() as u64;
        Ok(())
    }
}

const BATCH: usize = 64;

fn flush_batch(
    ctx: &mut OutCtx,
    batch: &mut Vec<(u64, Vec<u8>)>,
    data_key: &[u8; 32],
    core_body: &[u8],
    archive_id: &[u8; 16],
    level: i32,
    chunk_offsets: &mut Vec<u64>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    // comprimi + cifra in parallelo (l'ordine del Vec è preservato da rayon)
    let records: Vec<Vec<u8>> = batch
        .par_iter()
        .map(|(index, data)| -> Result<Vec<u8>> {
            let packed = compress::compress_block(data, level)?;
            let nonce = crypto::random_nonce();
            let aad = aad_chunk(core_body, archive_id, *index);
            let ct = crypto::seal(data_key, &nonce, &aad, &packed)?;
            let mut rec = Vec::with_capacity(NONCE_LEN + 4 + ct.len());
            rec.extend_from_slice(&nonce);
            rec.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            rec.extend_from_slice(&ct);
            Ok(rec)
        })
        .collect::<Result<Vec<_>>>()?;

    for rec in records {
        chunk_offsets.push(ctx.offset); // offset di inizio del record
        ctx.hashed(&rec)?;
    }
    batch.clear();
    Ok(())
}

/// Crea un archivio scrivendolo direttamente su file, a streaming.
pub fn pack_to_file(
    files: &[InputFile],
    out_path: &Path,
    secret: &Secret,
    signing_key: &SigningKey,
    zstd_level: i32,
    argon: &ArgonParams,
) -> Result<PackStats> {
    let mut archive_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut archive_id);
    let mut mfk = keys::random_mfk();

    let body_len = CoreHeader::body_len();
    let slot_region_start = CoreHeader::slot_region_start_for_body_len(body_len);

    let mut flags = format::flags::SIGNED;
    if secret.has_keyfile() {
        flags |= format::flags::KEYFILE_REQUIRED;
    }

    let core = CoreHeader {
        format_version: format::FORMAT_VERSION,
        flags,
        aead_algo: format::AEAD_XCHACHA20POLY1305,
        compress_algo: format::COMPRESS_ZSTD,
        kdf_algo: format::KDF_ARGON2ID,
        cdc_min: format::CDC_MIN,
        cdc_avg: format::CDC_AVG,
        cdc_max: format::CDC_MAX,
        signer_pubkey: signing_key.verifying_key().to_bytes(),
        archive_id,
        slot_region_start,
        slot_region_len: SLOT_REGION_LEN as u64,
    };
    let core_body = core.body_bytes()?;

    let file = File::create(out_path)?;
    let mut ctx = OutCtx {
        w: BufWriter::new(file),
        hasher: blake3::Hasher::new(),
        offset: 0,
    };

    // header (incluso nel digest firmato)
    ctx.hashed(&format::MAGIC)?;
    ctx.hashed(&(core_body.len() as u32).to_le_bytes())?;
    ctx.hashed(&core_body)?;
    debug_assert_eq!(ctx.offset, slot_region_start);

    // regione keyslot (NON firmata)
    let slot0 = keyslot::wrap_slot(&mfk, secret, argon.mem_kib, argon.iters, argon.lanes, &core_body)?;
    let mut slots: [KeySlot; MAX_SLOTS] = std::array::from_fn(|_| KeySlot::empty());
    slots[0] = slot0;
    let region = keyslot::serialize_region(&slots, &mfk);
    ctx.plain(&region)?;

    let data_keys = keys::derive_data_keys(&mfk);
    let chunk_stream_off = ctx.offset;

    let mut deduper = crate::chunk::Deduper::new();
    let mut chunk_offsets: Vec<u64> = Vec::new();
    let mut entries: Vec<FileEntry> = Vec::with_capacity(files.len());
    let mut total_orig: u64 = 0;

    for f in files {
        let src = File::open(&f.abs_path)?;
        let chunker = StreamCDC::new(src, core.cdc_min, core.cdc_avg, core.cdc_max);
        let mut refs: Vec<u64> = Vec::new();
        let mut file_hasher = blake3::Hasher::new();
        let mut size: u64 = 0;
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::with_capacity(BATCH);

        for res in chunker {
            let cd = res.map_err(|_| AxError::Corrupt("chunking in streaming fallito"))?;
            file_hasher.update(&cd.data);
            size += cd.data.len() as u64;
            let h = *blake3::hash(&cd.data).as_bytes();
            let (index, is_new) = deduper.get_or_insert(&h);
            refs.push(index);
            if is_new {
                batch.push((index, cd.data));
                if batch.len() >= BATCH {
                    flush_batch(&mut ctx, &mut batch, &data_keys.data_key, &core_body, &archive_id, zstd_level, &mut chunk_offsets)?;
                }
            }
        }
        flush_batch(&mut ctx, &mut batch, &data_keys.data_key, &core_body, &archive_id, zstd_level, &mut chunk_offsets)?;

        total_orig += size;
        entries.push(FileEntry {
            path: f.rel_path.clone(),
            size,
            mode: f.mode,
            chunks: refs,
            blake3: *file_hasher.finalize().as_bytes(),
        });
    }
    let chunk_count = deduper.unique_count();

    // indice cifrato (con la tabella offset)
    let index_off = ctx.offset;
    let index_pt = IndexPlaintext { entries, chunk_offsets };
    let index_bytes = bincode::serialize(&index_pt)?;
    let inonce = crypto::random_nonce();
    let index_ct = crypto::seal(&data_keys.index_key, &inonce, &aad_index(&core_body), &index_bytes)?;
    let rec_start = ctx.offset;
    ctx.hashed(&inonce)?;
    ctx.hashed(&(index_ct.len() as u32).to_le_bytes())?;
    ctx.hashed(&index_ct)?;
    let index_ct_len = ctx.offset - rec_start;

    // footer
    let footer = Footer {
        chunk_count,
        chunk_stream_off,
        index_off,
        index_ct_len,
        total_orig_size: total_orig,
    };
    let fbody = bincode::serialize(&footer)?;
    ctx.hashed(&fbody)?;
    ctx.hashed(&(fbody.len() as u32).to_le_bytes())?;
    ctx.hashed(&format::FOOTER_MAGIC)?;

    // firma (sul digest che esclude la regione keyslot)
    let digest = *ctx.hasher.finalize().as_bytes();
    let signature = crypto::sign(signing_key, &digest);
    ctx.plain(&signature)?;
    ctx.w.flush()?;

    let archive_size = ctx.offset;
    mfk.zeroize();
    Ok(PackStats {
        orig_size: total_orig,
        archive_size,
        chunk_count,
    })
}

// =====================================================================
// Lettura / UNPACK (streaming, accesso casuale ai blocchi)
// =====================================================================

pub struct ArchiveInfo {
    pub header: CoreHeader,
    pub footer: Footer,
    pub index: IndexPlaintext,
    pub slots_used: usize,
    pub argon_mem_kib: u32,
    pub argon_iters: u32,
    pub argon_lanes: u8,
}

fn read_at(f: &mut File, off: u64, len: usize) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b)?;
    Ok(b)
}

fn read_record_at(f: &mut File, off: u64) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    f.seek(SeekFrom::Start(off))?;
    let mut nonce = [0u8; NONCE_LEN];
    f.read_exact(&mut nonce)?;
    let mut lb = [0u8; 4];
    f.read_exact(&mut lb)?;
    let l = u32::from_le_bytes(lb) as usize;
    let mut ct = vec![0u8; l];
    f.read_exact(&mut ct)?;
    Ok((nonce, ct))
}

fn hash_range(f: &mut File, h: &mut blake3::Hasher, start: u64, end: u64) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    f.seek(SeekFrom::Start(start))?;
    let mut remaining = end - start;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        h.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(())
}

fn read_footer(f: &mut File, flen: u64) -> Result<Footer> {
    if flen < 64 + 8 {
        return Err(AxError::Corrupt("file troppo corto"));
    }
    let base = flen - 64; // inizio della firma
    let magic = read_at(f, base - 4, 4)?;
    if magic != format::FOOTER_MAGIC {
        return Err(AxError::Corrupt("footer magic assente"));
    }
    let len = u32::from_le_bytes(read_at(f, base - 8, 4)?.try_into().unwrap()) as u64;
    let fstart = base - 8 - len;
    let fbody = read_at(f, fstart, len as usize)?;
    Ok(bincode::deserialize(&fbody)?)
}

/// Verifica la firma leggendo il file a streaming (niente caricamento totale).
pub fn verify_signature_file(path: &Path, trusted: Option<&[u8; 32]>) -> Result<CoreHeader> {
    let mut f = File::open(path)?;
    let flen = f.metadata()?.len();
    if flen < 64 {
        return Err(AxError::Corrupt("file troppo corto per la firma"));
    }
    let (core, _body) = CoreHeader::read_from(&mut f)?;
    if let Some(t) = trusted {
        if &core.signer_pubkey != t {
            return Err(AxError::UntrustedSigner);
        }
    }
    let sig_start = flen - 64;
    let sig_vec = read_at(&mut f, sig_start, 64)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_vec);

    let mut hasher = blake3::Hasher::new();
    hash_range(&mut f, &mut hasher, 0, core.slot_region_start)?;
    hash_range(&mut f, &mut hasher, core.slot_region_start + core.slot_region_len, sig_start)?;
    let digest = *hasher.finalize().as_bytes();
    crypto::verify(&core.signer_pubkey, &digest, &sig)?;
    Ok(core)
}

struct Opened {
    core: CoreHeader,
    core_body: Vec<u8>,
    data_keys: DerivedKeys,
    footer: Footer,
    index: IndexPlaintext,
    slots_used: usize,
    argon: (u32, u32, u8),
}

/// Verifica firma, apre uno slot, deriva le chiavi e carica l'indice.
fn open_archive(path: &Path, secret: &Secret, trusted: Option<&[u8; 32]>) -> Result<Opened> {
    let core = verify_signature_file(path, trusted)?;
    let mut f = File::open(path)?;
    let (_c, core_body) = CoreHeader::read_from(&mut f)?;

    let region = read_at(&mut f, core.slot_region_start, core.slot_region_len as usize)?;
    let (mut mfk, opened) = keyslot::open_region(&region, secret, &core_body)?;
    let slots = keyslot::parse_slots(&region)?;
    let slots_used = keyslot::used_count(&slots);
    let os = &slots[opened];
    let argon = (os.argon_mem_kib, os.argon_iters, os.argon_lanes);

    let data_keys = keys::derive_data_keys(&mfk);
    mfk.zeroize();

    let flen = f.metadata()?.len();
    let footer = read_footer(&mut f, flen)?;
    let (nonce, ct) = read_record_at(&mut f, footer.index_off)?;
    let index_bytes = crypto::open(&data_keys.index_key, &nonce, &aad_index(&core_body), &ct)?;
    let index: IndexPlaintext = bincode::deserialize(&index_bytes)?;

    Ok(Opened {
        core,
        core_body,
        data_keys,
        footer,
        index,
        slots_used,
        argon,
    })
}

/// Legge header, footer e indice (per list/info).
pub fn read_index_file(path: &Path, secret: &Secret, trusted: Option<&[u8; 32]>) -> Result<ArchiveInfo> {
    let o = open_archive(path, secret, trusted)?;
    Ok(ArchiveInfo {
        header: o.core,
        footer: o.footer,
        index: o.index,
        slots_used: o.slots_used,
        argon_mem_kib: o.argon.0,
        argon_iters: o.argon.1,
        argon_lanes: o.argon.2,
    })
}

/// Estrae tutti i file in `out_dir`, leggendo un blocco alla volta.
pub fn unpack_file(
    path: &Path,
    secret: &Secret,
    trusted: Option<&[u8; 32]>,
    out_dir: &Path,
) -> Result<Vec<String>> {
    let o = open_archive(path, secret, trusted)?;
    let mut src = File::open(path)?;

    let mut written = Vec::with_capacity(o.index.entries.len());
    for entry in &o.index.entries {
        let dest = out_dir.join(sanitize_rel(&entry.path));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = BufWriter::new(File::create(&dest)?);
        let mut fh = blake3::Hasher::new();

        for &ci in &entry.chunks {
            let off = *o
                .index
                .chunk_offsets
                .get(ci as usize)
                .ok_or(AxError::Corrupt("offset blocco mancante"))?;
            let (nonce, ct) = read_record_at(&mut src, off)?;
            let aad = aad_chunk(&o.core_body, &o.core.archive_id, ci);
            let packed = crypto::open(&o.data_keys.data_key, &nonce, &aad, &ct)?;
            let plain = compress::decompress_block(&packed)?;
            out.write_all(&plain)?;
            fh.update(&plain);
        }
        out.flush()?;
        if *fh.finalize().as_bytes() != entry.blake3 {
            return Err(AxError::IntegrityFailed(entry.path.clone()));
        }
        written.push(entry.path.clone());
    }
    Ok(written)
}

fn sanitize_rel(rel: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in rel.split(['/', '\\']) {
        match comp {
            "" | "." | ".." => continue,
            _ => {
                let clean = comp.trim_end_matches(':');
                if !clean.is_empty() {
                    out.push(clean);
                }
            }
        }
    }
    out
}

// =====================================================================
// GESTIONE CHIAVI (in-place sulla regione keyslot, niente ricifratura)
// =====================================================================

struct OpenRw {
    file: File,
    core_body: Vec<u8>,
    region_start: u64,
    region: Vec<u8>,
}

fn open_rw(path: &Path) -> Result<OpenRw> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let (core, core_body) = CoreHeader::read_from(&mut file)?;
    let region_start = core.slot_region_start;
    let region = read_at(&mut file, region_start, core.slot_region_len as usize)?;
    Ok(OpenRw {
        file,
        core_body,
        region_start,
        region,
    })
}

fn write_region(of: &mut OpenRw, region: &[u8]) -> Result<()> {
    of.file.seek(SeekFrom::Start(of.region_start))?;
    of.file.write_all(region)?;
    of.file.flush()?;
    Ok(())
}

/// Cambia la password/keyfile dello slot aperto da `old`. Dati e firma intatti.
pub fn changepw(path: &Path, old: &Secret, new: &Secret, argon: &ArgonParams) -> Result<()> {
    let mut of = open_rw(path)?;
    let (mut mfk, idx) = keyslot::open_region(&of.region, old, &of.core_body)?;
    let mut slots = keyslot::parse_slots(&of.region)?;
    slots[idx] = keyslot::wrap_slot(&mfk, new, argon.mem_kib, argon.iters, argon.lanes, &of.core_body)?;
    let region = keyslot::serialize_region(&slots, &mfk);
    mfk.zeroize();
    write_region(&mut of, &region)
}

/// Aggiunge una nuova chiave d'accesso.
pub fn addkey(path: &Path, existing: &Secret, newsec: &Secret, argon: &ArgonParams) -> Result<()> {
    let mut of = open_rw(path)?;
    let (mut mfk, _) = keyslot::open_region(&of.region, existing, &of.core_body)?;
    let mut slots = keyslot::parse_slots(&of.region)?;
    let free = keyslot::first_free(&slots).ok_or(AxError::SlotFull)?;
    slots[free] = keyslot::wrap_slot(&mfk, newsec, argon.mem_kib, argon.iters, argon.lanes, &of.core_body)?;
    let region = keyslot::serialize_region(&slots, &mfk);
    mfk.zeroize();
    write_region(&mut of, &region)
}

/// Rimuove la chiave che apre con `target`. Non si può togliere l'ultima.
pub fn rmkey(path: &Path, existing: &Secret, target: &Secret) -> Result<()> {
    let mut of = open_rw(path)?;
    let (mut mfk, _) = keyslot::open_region(&of.region, existing, &of.core_body)?;
    let mut slots = keyslot::parse_slots(&of.region)?;
    if keyslot::used_count(&slots) <= 1 {
        mfk.zeroize();
        return Err(AxError::LastSlot);
    }
    let idx = keyslot::find_slot_index(&of.region, target, &of.core_body)?;
    slots[idx] = KeySlot::empty();
    let region = keyslot::serialize_region(&slots, &mfk);
    mfk.zeroize();
    write_region(&mut of, &region)
}
