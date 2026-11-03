//! Regione keyslot: cifratura a busta e gestione di più chiavi d'accesso.
//!
//! La regione ha dimensione **fissa** (riservati `MAX_SLOTS` slot) e sta subito
//! dopo l'header core. Così può essere riscritta sul posto — cambiare password,
//! aggiungere o togliere una chiave — senza toccare i dati né la firma.
//!
//! Ogni slot avvolge la stessa MFK con una KEK diversa (password+keyfile).
//! Un MAC (keyed-hash con la MFK) sull'insieme degli slot rileva manomissioni
//! della lista d'accesso una volta che l'archivio viene aperto.

use rand::RngCore;
use zeroize::Zeroize;

use crate::crypto;
use crate::error::{AxError, Result};
use crate::keys::{self, Secret};

/// Numero massimo di slot (chiavi) per archivio.
pub const MAX_SLOTS: usize = 8;
/// Dimensione in byte di uno slot serializzato.
pub const SLOT_SIZE: usize = 1 + 4 + 4 + 1 + 1 + 16 + crypto::NONCE_LEN + 48;
/// MFK(32) + tag(16) = 48 byte avvolti.
pub const WRAPPED_LEN: usize = 48;
/// Dimensione totale della regione: slot + MAC finale.
pub const SLOT_REGION_LEN: usize = MAX_SLOTS * SLOT_SIZE + 32;

/// Flag di slot.
pub mod slot_flags {
    pub const KEYFILE_REQUIRED: u8 = 1 << 0;
}

/// Uno slot d'accesso.
#[derive(Clone)]
pub struct KeySlot {
    pub used: bool,
    pub argon_mem_kib: u32,
    pub argon_iters: u32,
    pub argon_lanes: u8,
    pub flags: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; crypto::NONCE_LEN],
    pub wrapped: [u8; WRAPPED_LEN],
}

impl KeySlot {
    pub fn empty() -> Self {
        KeySlot {
            used: false,
            argon_mem_kib: 0,
            argon_iters: 0,
            argon_lanes: 0,
            flags: 0,
            salt: [0; 16],
            nonce: [0; crypto::NONCE_LEN],
            wrapped: [0; WRAPPED_LEN],
        }
    }

    fn to_bytes(&self) -> [u8; SLOT_SIZE] {
        let mut b = [0u8; SLOT_SIZE];
        let mut o = 0;
        b[o] = self.used as u8;
        o += 1;
        b[o..o + 4].copy_from_slice(&self.argon_mem_kib.to_le_bytes());
        o += 4;
        b[o..o + 4].copy_from_slice(&self.argon_iters.to_le_bytes());
        o += 4;
        b[o] = self.argon_lanes;
        o += 1;
        b[o] = self.flags;
        o += 1;
        b[o..o + 16].copy_from_slice(&self.salt);
        o += 16;
        b[o..o + crypto::NONCE_LEN].copy_from_slice(&self.nonce);
        o += crypto::NONCE_LEN;
        b[o..o + WRAPPED_LEN].copy_from_slice(&self.wrapped);
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        let mut o = 0;
        let used = b[o] != 0;
        o += 1;
        let argon_mem_kib = u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        o += 4;
        let argon_iters = u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        o += 4;
        let argon_lanes = b[o];
        o += 1;
        let flags = b[o];
        o += 1;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[o..o + 16]);
        o += 16;
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&b[o..o + crypto::NONCE_LEN]);
        o += crypto::NONCE_LEN;
        let mut wrapped = [0u8; WRAPPED_LEN];
        wrapped.copy_from_slice(&b[o..o + WRAPPED_LEN]);
        KeySlot {
            used,
            argon_mem_kib,
            argon_iters,
            argon_lanes,
            flags,
            salt,
            nonce,
            wrapped,
        }
    }
}

/// Crea uno slot che avvolge `mfk` con il segreto dato.
pub fn wrap_slot(
    mfk: &[u8; 32],
    secret: &Secret,
    mem_kib: u32,
    iters: u32,
    lanes: u8,
    core_body: &[u8],
) -> Result<KeySlot> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let nonce = crypto::random_nonce();

    let mut kek = keys::derive_kek(secret, mem_kib, iters, lanes, &salt)?;
    let ct = crypto::seal(&kek, &nonce, core_body, mfk)?;
    kek.zeroize();
    if ct.len() != WRAPPED_LEN {
        return Err(AxError::Encrypt);
    }
    let mut wrapped = [0u8; WRAPPED_LEN];
    wrapped.copy_from_slice(&ct);

    let flags = if secret.has_keyfile() {
        slot_flags::KEYFILE_REQUIRED
    } else {
        0
    };
    Ok(KeySlot {
        used: true,
        argon_mem_kib: mem_kib,
        argon_iters: iters,
        argon_lanes: lanes,
        flags,
        salt,
        nonce,
        wrapped,
    })
}

/// Serializza gli slot in una regione completa (slot + MAC con la MFK).
pub fn serialize_region(slots: &[KeySlot; MAX_SLOTS], mfk: &[u8; 32]) -> [u8; SLOT_REGION_LEN] {
    let mut out = [0u8; SLOT_REGION_LEN];
    let mut o = 0;
    for s in slots.iter() {
        out[o..o + SLOT_SIZE].copy_from_slice(&s.to_bytes());
        o += SLOT_SIZE;
    }
    let mac = compute_mac(mfk, &out[..MAX_SLOTS * SLOT_SIZE]);
    out[o..o + 32].copy_from_slice(&mac);
    out
}

/// Parsa gli slot dalla regione (senza verificare il MAC).
pub fn parse_slots(region: &[u8]) -> Result<[KeySlot; MAX_SLOTS]> {
    if region.len() != SLOT_REGION_LEN {
        return Err(AxError::Corrupt("regione keyslot di dimensione errata"));
    }
    let mut slots: [KeySlot; MAX_SLOTS] = std::array::from_fn(|_| KeySlot::empty());
    for (i, slot) in slots.iter_mut().enumerate() {
        let start = i * SLOT_SIZE;
        *slot = KeySlot::from_bytes(&region[start..start + SLOT_SIZE]);
    }
    Ok(slots)
}

/// MAC sui byte degli slot (senza il campo MAC), con chiave = MFK.
pub fn compute_mac(mfk: &[u8; 32], slots_bytes: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(mfk, slots_bytes).into()
}

/// Prova ad aprire la regione con il segreto: restituisce (MFK, indice slot).
/// Verifica anche il MAC della lista slot.
pub fn open_region(region: &[u8], secret: &Secret, core_body: &[u8]) -> Result<([u8; 32], usize)> {
    let slots = parse_slots(region)?;
    for (i, slot) in slots.iter().enumerate() {
        // slot vuoto, o con parametri KDF fuori limite (danneggiato): saltato
        if !slot.used
            || !crate::format::argon_params_ok(
                slot.argon_mem_kib,
                slot.argon_iters,
                slot.argon_lanes,
            )
        {
            continue;
        }
        let mut kek = keys::derive_kek(
            secret,
            slot.argon_mem_kib,
            slot.argon_iters,
            slot.argon_lanes,
            &slot.salt,
        )?;
        let res = crypto::open(&kek, &slot.nonce, core_body, &slot.wrapped);
        kek.zeroize();
        if let Ok(mfk_vec) = res {
            if mfk_vec.len() != 32 {
                return Err(AxError::Decrypt);
            }
            let mut mfk = [0u8; 32];
            mfk.copy_from_slice(&mfk_vec);
            // verifica l'integrità della lista slot
            let expect = &region[MAX_SLOTS * SLOT_SIZE..];
            let got = compute_mac(&mfk, &region[..MAX_SLOTS * SLOT_SIZE]);
            if expect != got {
                mfk.zeroize();
                return Err(AxError::SlotsTampered);
            }
            return Ok((mfk, i));
        }
    }
    Err(AxError::NoMatchingSlot)
}

/// Trova l'indice dello slot che si apre con `secret` (senza restituire la MFK).
pub fn find_slot_index(region: &[u8], secret: &Secret, core_body: &[u8]) -> Result<usize> {
    let slots = parse_slots(region)?;
    for (i, slot) in slots.iter().enumerate() {
        // slot vuoto, o con parametri KDF fuori limite (danneggiato): saltato
        if !slot.used
            || !crate::format::argon_params_ok(
                slot.argon_mem_kib,
                slot.argon_iters,
                slot.argon_lanes,
            )
        {
            continue;
        }
        let mut kek = keys::derive_kek(
            secret,
            slot.argon_mem_kib,
            slot.argon_iters,
            slot.argon_lanes,
            &slot.salt,
        )?;
        let res = crypto::open(&kek, &slot.nonce, core_body, &slot.wrapped);
        kek.zeroize();
        if res.is_ok() {
            return Ok(i);
        }
    }
    Err(AxError::NoMatchingSlot)
}

/// Conta gli slot attualmente usati.
pub fn used_count(slots: &[KeySlot; MAX_SLOTS]) -> usize {
    slots.iter().filter(|s| s.used).count()
}

/// Indice del primo slot libero, se esiste.
pub fn first_free(slots: &[KeySlot; MAX_SLOTS]) -> Option<usize> {
    slots.iter().position(|s| !s.used)
}
