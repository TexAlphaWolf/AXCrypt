//! Identità di firma: coppia di chiavi Ed25519, generazione e persistenza.
//!
//! Il file identità (`.axid`) contiene la chiave PRIVATA: va trattato come un
//! segreto (tenerlo sulla USB con il keyfile). Il file `.axid.pub` contiene
//! solo la chiave pubblica, condivisibile e usata come "trust anchor" in
//! fase di estrazione.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use crate::error::{AxError, Result};

const ID_MAGIC: [u8; 8] = *b"AXID1\0\0\0";

/// Genera una nuova coppia di chiavi di firma.
pub fn generate() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Salva l'identità (chiave privata + pubblica) su file.
/// Layout: `ID_MAGIC || seed(32) || pub(32)`.
pub fn save_identity(path: impl AsRef<Path>, sk: &SigningKey) -> Result<()> {
    let mut buf = Vec::with_capacity(8 + 64);
    buf.extend_from_slice(&ID_MAGIC);
    buf.extend_from_slice(&sk.to_bytes()); // seed privato (32)
    buf.extend_from_slice(sk.verifying_key().as_bytes()); // pub (32)
    fs::write(&path, &buf)?;
    buf.zeroize();
    Ok(())
}

/// Carica un'identità da file.
pub fn load_identity(path: impl AsRef<Path>) -> Result<SigningKey> {
    let data = fs::read(&path)?;
    if data.len() != 8 + 64 || data[..8] != ID_MAGIC {
        return Err(AxError::BadIdentity);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[8..40]);
    let sk = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(sk)
}

/// Salva la sola chiave pubblica come testo esadecimale (trust anchor).
pub fn save_public(path: impl AsRef<Path>, vk: &VerifyingKey) -> Result<()> {
    let hex = to_hex(vk.as_bytes());
    fs::write(&path, hex.as_bytes())?;
    Ok(())
}

/// Carica una chiave pubblica da file esadecimale.
pub fn load_public(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let text = fs::read_to_string(&path)?;
    from_hex(text.trim()).ok_or(AxError::BadIdentity)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
