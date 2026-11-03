//! Tipo d'errore unico per il core.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AxError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("struttura binaria non valida: {0}")]
    Decode(&'static str),

    #[error("limite del formato superato: {0}")]
    FormatLimit(&'static str),

    #[error("magic o versione del formato non validi")]
    BadMagic,

    #[error("algoritmo non supportato (campo {0})")]
    UnsupportedAlgo(&'static str),

    #[error("derivazione chiave (Argon2id) fallita: {0}")]
    Kdf(String),

    #[error("decifratura fallita: password/keyfile errati o dati manomessi")]
    Decrypt,

    #[error("cifratura fallita")]
    Encrypt,

    #[error("password/keyfile errati: nessuno slot corrisponde")]
    NoMatchingSlot,

    #[error("lista degli slot (accesso) manomessa")]
    SlotsTampered,

    #[error("non ci sono slot liberi (massimo raggiunto)")]
    SlotFull,

    #[error("impossibile rimuovere l'ultimo slot: l'archivio resterebbe inaccessibile")]
    LastSlot,

    #[error("firma non valida: l'archivio non è autentico o è stato manomesso")]
    BadSignature,

    #[error("archivio firmato da una chiave non fidata")]
    UntrustedSigner,

    #[error("archivio troncato o corrotto: {0}")]
    Corrupt(&'static str),

    #[error("verifica integrità file fallita: {0}")]
    IntegrityFailed(String),

    #[error("file identità non valido")]
    BadIdentity,

    #[error("file di recupero non valido o di versione diversa")]
    RecoveryBadMagic,

    #[error("il file di recupero non corrisponde a questo archivio")]
    RecoveryMismatch,

    #[error("danno troppo esteso: {corrupt} blocchi corrotti, parità disponibile {parity}")]
    RecoveryTooDamaged { corrupt: usize, parity: usize },

    #[error("parametri di recupero non validi: {0}")]
    RecoveryParams(String),
}

pub type Result<T> = std::result::Result<T, AxError>;
