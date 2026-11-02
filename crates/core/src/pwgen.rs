//! Generatore di password e stima della robustezza (entropia).
//!
//! Selezione uniforme da un RNG di sistema; garantisce almeno un carattere per
//! ogni classe scelta, poi mescola. La stima di entropia usa la dimensione del
//! pool dei caratteri effettivamente presenti.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// Classi di caratteri da includere.
#[derive(Clone, Copy)]
pub struct PwOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PwOptions {
    fn default() -> Self {
        PwOptions {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
        }
    }
}

impl PwOptions {
    fn pools(&self) -> Vec<&'static [u8]> {
        let mut v = Vec::new();
        if self.lower {
            v.push(LOWER);
        }
        if self.upper {
            v.push(UPPER);
        }
        if self.digits {
            v.push(DIGITS);
        }
        if self.symbols {
            v.push(SYMBOLS);
        }
        v
    }

    /// Dimensione totale del pool di caratteri.
    pub fn pool_size(&self) -> usize {
        self.pools().iter().map(|p| p.len()).sum()
    }
}

/// Genera una password secondo le opzioni. Se nessuna classe è selezionata,
/// usa le minuscole come fallback. La lunghezza è almeno pari al numero di
/// classi selezionate.
pub fn generate_password(opts: &PwOptions) -> String {
    let mut pools = opts.pools();
    if pools.is_empty() {
        pools.push(LOWER);
    }
    let all: Vec<u8> = pools.iter().flat_map(|p| p.iter().copied()).collect();
    let len = opts.length.max(pools.len()).max(1);

    let mut rng = OsRng;
    let mut chars: Vec<u8> = Vec::with_capacity(len);
    // almeno un carattere per classe selezionata
    for pool in &pools {
        chars.push(pool[rng.gen_range(0..pool.len())]);
    }
    // riempi il resto pescando dall'insieme totale
    while chars.len() < len {
        chars.push(all[rng.gen_range(0..all.len())]);
    }
    chars.shuffle(&mut rng);
    String::from_utf8(chars).unwrap_or_default()
}

/// Entropia in bit per una password lunga `len` su un pool di `pool_size`.
pub fn entropy_bits(len: usize, pool_size: usize) -> f64 {
    if pool_size <= 1 || len == 0 {
        return 0.0;
    }
    len as f64 * (pool_size as f64).log2()
}

/// Stima l'entropia di una password esistente in base alle classi presenti.
pub fn estimate_entropy(pw: &str) -> f64 {
    if pw.is_empty() {
        return 0.0;
    }
    let mut pool = 0usize;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += SYMBOLS.len();
    }
    entropy_bits(pw.chars().count(), pool.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lunghezza_e_classi() {
        let opts = PwOptions {
            length: 24,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
        };
        let pw = generate_password(&opts);
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn solo_cifre() {
        let opts = PwOptions {
            length: 10,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
        };
        let pw = generate_password(&opts);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(opts.pool_size(), 10);
    }

    #[test]
    fn entropia_cresce_con_lunghezza() {
        assert!(entropy_bits(20, 90) > entropy_bits(10, 90));
        assert!(estimate_entropy("aaaaaaaa") < estimate_entropy("aA1!aA1!"));
    }

    #[test]
    fn password_diverse() {
        let o = PwOptions::default();
        assert_ne!(generate_password(&o), generate_password(&o));
    }
}
