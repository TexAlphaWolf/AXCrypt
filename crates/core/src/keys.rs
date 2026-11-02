//! Derivazione delle chiavi per il formato v2 (cifratura a busta).
//!
//! - La chiave master dei dati (MFK) è casuale, non deriva dalla password.
//! - La password+keyfile derivano una KEK (key-encryption-key) che "avvolge"
//!   la MFK in uno slot (vedi `keyslot.rs`).
//! - Dalla MFK si derivano le sottochiavi che cifrano dati e indice.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AxError, Result};

/// Sottochiavi dei dati, derivate dalla MFK. Azzerate al drop.
#[derive(ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub data_key: [u8; 32],
    pub index_key: [u8; 32],
}

/// Segreto dell'utente: password + eventuale keyfile. Azzerato al drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    pub(crate) password: Vec<u8>,
    pub(crate) keyfile: Vec<u8>,
}

impl Secret {
    pub fn new(password: impl Into<Vec<u8>>, keyfile: Option<Vec<u8>>) -> Self {
        Secret {
            password: password.into(),
            keyfile: keyfile.unwrap_or_default(),
        }
    }

    pub fn has_keyfile(&self) -> bool {
        !self.keyfile.is_empty()
    }
}

/// Genera una chiave master casuale (MFK) da 32 byte.
pub fn random_mfk() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// Deriva la KEK dello slot: Argon2id(password) combinato col keyfile.
///
/// `pw_key = Argon2id(password, salt, params)`
/// `kek    = keyfile ? BLAKE3::keyed_hash(pw_key, keyfile) : pw_key`
pub fn derive_kek(
    secret: &Secret,
    mem_kib: u32,
    iters: u32,
    lanes: u8,
    salt: &[u8; 16],
) -> Result<[u8; 32]> {
    let params = Params::new(mem_kib, iters, lanes as u32, Some(32))
        .map_err(|e| AxError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut pw_key = [0u8; 32];
    argon
        .hash_password_into(&secret.password, salt, &mut pw_key)
        .map_err(|e| AxError::Kdf(e.to_string()))?;

    let kek = if secret.has_keyfile() {
        blake3::keyed_hash(&pw_key, &secret.keyfile).into()
    } else {
        pw_key
    };
    pw_key.zeroize();
    Ok(kek)
}

/// Deriva le sottochiavi dei dati dalla MFK.
pub fn derive_data_keys(mfk: &[u8; 32]) -> DerivedKeys {
    DerivedKeys {
        data_key: blake3::derive_key("axcrypt v3 data key", mfk),
        index_key: blake3::derive_key("axcrypt v3 index key", mfk),
    }
}
