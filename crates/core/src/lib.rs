//! AXCrypt core (formato v4, legge anche v3): compressione + cifratura a
//! busta + firma.
//! Pack/unpack a streaming (memoria limitata).
//!
//! API pubblica riusata da CLI e GUI. Nessun algoritmo crittografico è
//! implementato qui: si usano solo librerie verificate.

pub mod archive;
pub mod chunk;
pub mod codec;
pub mod compress;
pub mod crypto;
pub mod error;
pub mod format;
pub mod identity;
pub mod keys;
pub mod keyslot;
pub mod pwgen;
pub mod recovery;

#[cfg(test)]
mod compat_tests;

pub use archive::{
    addkey, changepw, pack_to_file, read_index_file, rmkey, unpack_file, verify_signature_file,
    ArchiveInfo, InputFile, PackStats,
};
pub use error::{AxError, Result};
pub use format::ArgonParams;
pub use keys::Secret;
pub use pwgen::{estimate_entropy, generate_password, PwOptions};
pub use recovery::{protect, repair, RecoveryStats, RepairReport};

use rand::RngCore;

/// Genera un keyfile casuale da `len` byte (consigliato 32 = 256 bit).
pub fn make_keyfile(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// =====================================================================
// TEST
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmpdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut n = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut n);
        p.push(format!("axtest-{}", u64::from_le_bytes(n)));
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// Set vario: testo ripetitivo, duplicato (dedup), binario incomprimibile,
    /// file vuoto, file annidato.
    fn make_sample(dir: &Path) -> Vec<InputFile> {
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        let testo = "riga di testo ripetuta ".repeat(40000);
        fs::write(src.join("testo.txt"), &testo).unwrap();
        fs::write(src.join("dup.txt"), &testo).unwrap();
        let mut bin = vec![0u8; 500_000];
        rand::rngs::OsRng.fill_bytes(&mut bin);
        fs::write(src.join("dati.bin"), &bin).unwrap();
        fs::write(src.join("vuoto.dat"), b"").unwrap();
        fs::write(src.join("sub").join("nota.txt"), b"nota breve").unwrap();

        [
            "testo.txt",
            "dup.txt",
            "dati.bin",
            "vuoto.dat",
            "sub/nota.txt",
        ]
        .iter()
        .map(|rel| {
            let abs = if rel.contains('/') {
                src.join("sub").join("nota.txt")
            } else {
                src.join(rel)
            };
            InputFile {
                rel_path: (*rel).into(),
                abs_path: abs,
                mode: 0,
            }
        })
        .collect()
    }

    fn secret(pw: &str, kf: Option<Vec<u8>>) -> Secret {
        Secret::new(pw.as_bytes().to_vec(), kf)
    }

    /// Crea un archivio su file e restituisce (percorso, trusted, files, src).
    fn pack_sample(dir: &Path, sec: &Secret) -> (PathBuf, [u8; 32], Vec<InputFile>, PathBuf) {
        let files = make_sample(dir);
        let sk = identity::generate();
        let trusted = sk.verifying_key().to_bytes();
        let axc = dir.join("a.axc");
        pack_to_file(
            &files,
            &axc,
            sec,
            &sk,
            compress::DEFAULT_LEVEL,
            &ArgonParams::fast(),
        )
        .unwrap();
        (axc, trusted, files, dir.join("src"))
    }

    fn compare_extracted(out: &Path, files: &[InputFile]) {
        for f in files {
            let original = fs::read(&f.abs_path).unwrap();
            let restored = fs::read(out.join(&f.rel_path)).unwrap();
            assert_eq!(original, restored, "file diverso: {}", f.rel_path);
        }
    }

    #[test]
    fn roundtrip_e_integrita() {
        let dir = tmpdir();
        let sec = secret("Password-Forte-123", Some(make_keyfile(32)));
        let (axc, trusted, files, _src) = pack_sample(&dir, &sec);

        let info = read_index_file(&axc, &sec, Some(&trusted)).unwrap();
        assert_eq!(info.index.entries.len(), 5);
        assert_eq!(info.slots_used, 1);

        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        let w = unpack_file(&axc, &sec, Some(&trusted), &out).unwrap();
        assert_eq!(w.len(), 5);
        compare_extracted(&out, &files);
    }

    #[test]
    fn dedup_condivide_i_blocchi() {
        let dir = tmpdir();
        let sec = secret("pw-dedup", Some(make_keyfile(32)));
        let (axc, trusted, _f, _s) = pack_sample(&dir, &sec);
        let info = read_index_file(&axc, &sec, Some(&trusted)).unwrap();
        let testo = &info
            .index
            .entries
            .iter()
            .find(|e| e.path == "testo.txt")
            .unwrap()
            .chunks;
        let dup = &info
            .index
            .entries
            .iter()
            .find(|e| e.path == "dup.txt")
            .unwrap()
            .chunks;
        assert_eq!(
            testo, dup,
            "i file identici devono referenziare gli stessi blocchi"
        );
    }

    #[test]
    fn password_errata_fallisce() {
        let dir = tmpdir();
        let kf = make_keyfile(32);
        let sec = secret("giusta", Some(kf.clone()));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let wrong = secret("sbagliata", Some(kf));
        assert!(matches!(
            read_index_file(&axc, &wrong, None),
            Err(AxError::NoMatchingSlot)
        ));
    }

    #[test]
    fn keyfile_errato_fallisce() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let wrong = secret("pw", Some(make_keyfile(32)));
        assert!(read_index_file(&axc, &wrong, None).is_err());
    }

    #[test]
    fn firmatario_non_fidato_rifiutato() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let altra = identity::generate().verifying_key().to_bytes();
        assert!(matches!(
            read_index_file(&axc, &sec, Some(&altra)),
            Err(AxError::UntrustedSigner)
        ));
    }

    #[test]
    fn dati_manomessi_rifiutati() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, trusted, _f, _s) = pack_sample(&dir, &sec);
        // altera un byte a metà file (nello stream dei blocchi)
        let mut bytes = fs::read(&axc).unwrap();
        let pos = bytes.len() / 2;
        bytes[pos] ^= 0xFF;
        fs::write(&axc, &bytes).unwrap();
        assert!(read_index_file(&axc, &sec, Some(&trusted)).is_err());
    }

    #[test]
    fn lista_slot_manomessa_rilevata() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, trusted, _f, _s) = pack_sample(&dir, &sec);
        let core = verify_signature_file(&axc, Some(&trusted)).unwrap();
        let mut bytes = fs::read(&axc).unwrap();
        let mac_byte = (core.slot_region_start + core.slot_region_len - 1) as usize;
        bytes[mac_byte] ^= 0xFF;
        fs::write(&axc, &bytes).unwrap();
        // la firma resta valida (non copre i keyslot)...
        assert!(verify_signature_file(&axc, Some(&trusted)).is_ok());
        // ...ma l'apertura rileva la manomissione
        assert!(matches!(
            read_index_file(&axc, &sec, None),
            Err(AxError::SlotsTampered)
        ));
    }

    #[test]
    fn changepw_cambia_solo_la_password() {
        let dir = tmpdir();
        let kf = make_keyfile(32);
        let old = secret("vecchia", Some(kf.clone()));
        let (axc, trusted, files, _s) = pack_sample(&dir, &old);

        let new = secret("nuova", Some(kf));
        changepw(&axc, &old, &new, &ArgonParams::fast()).unwrap();

        assert!(read_index_file(&axc, &old, None).is_err());
        let info = read_index_file(&axc, &new, Some(&trusted)).unwrap();
        assert_eq!(info.index.entries.len(), 5);
        assert!(verify_signature_file(&axc, Some(&trusted)).is_ok());

        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        unpack_file(&axc, &new, Some(&trusted), &out).unwrap();
        compare_extracted(&out, &files);
    }

    #[test]
    fn addkey_e_rmkey() {
        let dir = tmpdir();
        let kf = make_keyfile(32);
        let a = secret("chiave-A", Some(kf.clone()));
        let (axc, trusted, _f, _s) = pack_sample(&dir, &a);

        let b = secret("chiave-B", Some(kf));
        addkey(&axc, &a, &b, &ArgonParams::fast()).unwrap();
        assert!(read_index_file(&axc, &a, Some(&trusted)).is_ok());
        assert!(read_index_file(&axc, &b, Some(&trusted)).is_ok());
        assert_eq!(read_index_file(&axc, &a, None).unwrap().slots_used, 2);

        rmkey(&axc, &b, &a).unwrap();
        assert!(read_index_file(&axc, &a, None).is_err());
        assert!(read_index_file(&axc, &b, Some(&trusted)).is_ok());
        assert!(matches!(rmkey(&axc, &b, &b), Err(AxError::LastSlot)));
    }

    #[test]
    fn molti_file() {
        let dir = tmpdir();
        let src = dir.join("many");
        fs::create_dir_all(&src).unwrap();
        let mut files = Vec::new();
        for i in 0..200 {
            let name = format!("f{:03}.txt", i);
            let p = src.join(&name);
            fs::write(&p, format!("contenuto file {}\n", i).repeat(50)).unwrap();
            files.push(InputFile {
                rel_path: name,
                abs_path: p,
                mode: 0,
            });
        }
        let sec = secret("pw-many", Some(make_keyfile(32)));
        let sk = identity::generate();
        let trusted = sk.verifying_key().to_bytes();
        let axc = dir.join("many.axc");
        pack_to_file(
            &files,
            &axc,
            &sec,
            &sk,
            compress::DEFAULT_LEVEL,
            &ArgonParams::fast(),
        )
        .unwrap();
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        let w = unpack_file(&axc, &sec, Some(&trusted), &out).unwrap();
        assert_eq!(w.len(), 200);
        compare_extracted(&out, &files);
    }

    #[test]
    fn recovery_ripara_corruzione() {
        let dir = tmpdir();
        let sec = secret("pw-rec", Some(make_keyfile(32)));
        let (axc, trusted, files, _s) = pack_sample(&dir, &sec);

        // copia pristina per il confronto finale
        let pristine = fs::read(&axc).unwrap();

        // crea il recovery record al 20%
        let rec = dir.join("a.axc.rec");
        let stats = protect(&axc, &rec, 20).unwrap();
        assert!(stats.parity_count >= 1);

        // corrompi 5 regioni distinte dell'archivio
        let mut bytes = pristine.clone();
        let spacing = bytes.len() / 10;
        for k in 0..5 {
            let pos = (k * spacing + 7).min(bytes.len() - 1);
            bytes[pos] ^= 0xFF;
        }
        fs::write(&axc, &bytes).unwrap();
        // ora l'archivio corrotto non deve nemmeno aprirsi
        assert!(read_index_file(&axc, &sec, Some(&trusted)).is_err());

        // ripara
        let repaired = dir.join("a.repaired.axc");
        let report = repair(&axc, &rec, &repaired).unwrap();
        assert!(!report.already_ok);
        assert!(report.repaired >= 1);

        // il file riparato deve essere identico all'originale
        assert_eq!(fs::read(&repaired).unwrap(), pristine);

        // e deve tornare apribile ed estraibile
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        unpack_file(&repaired, &sec, Some(&trusted), &out).unwrap();
        compare_extracted(&out, &files);
    }

    #[test]
    fn recovery_gia_integro() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let rec = dir.join("a.axc.rec");
        protect(&axc, &rec, 10).unwrap();
        let out = dir.join("ok.axc");
        let report = repair(&axc, &rec, &out).unwrap();
        assert!(report.already_ok);
        assert_eq!(report.repaired, 0);
    }

    #[test]
    fn recovery_troppo_danno() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let pristine = fs::read(&axc).unwrap();
        // ridondanza minima: parità = 2 blocchi
        let rec = dir.join("a.axc.rec");
        let stats = protect(&axc, &rec, 1).unwrap();
        // corrompi più blocchi della parità disponibile
        let mut bytes = pristine.clone();
        let spacing = bytes.len() / (stats.parity_count + 5);
        for k in 0..(stats.parity_count + 3) {
            let pos = (k * spacing + 3).min(bytes.len() - 1);
            bytes[pos] ^= 0xAA;
        }
        fs::write(&axc, &bytes).unwrap();
        let out = dir.join("x.axc");
        assert!(matches!(
            repair(&axc, &rec, &out),
            Err(AxError::RecoveryTooDamaged { .. })
        ));
    }

    #[test]
    fn recovery_danni_anche_nella_parita() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, trusted, files, _s) = pack_sample(&dir, &sec);
        let pristine = fs::read(&axc).unwrap();
        let rec = dir.join("a.axc.rec");
        protect(&axc, &rec, 20).unwrap();

        // danneggia 10 punti dell'archivio...
        let mut bytes = pristine.clone();
        let step = bytes.len() / 12;
        for k in 1..=10 {
            bytes[k * step] ^= 0x5A;
        }
        fs::write(&axc, &bytes).unwrap();
        // ...e 3 punti nella parità del .rec (in coda al file)
        let mut rbytes = fs::read(&rec).unwrap();
        let n = rbytes.len();
        for k in 1..=3 {
            rbytes[n - k * 97] ^= 0xFF;
        }
        fs::write(&rec, &rbytes).unwrap();

        let out = dir.join("riparato.axc");
        let report = repair(&axc, &rec, &out).unwrap();
        assert!(report.repaired >= 1);
        assert_eq!(fs::read(&out).unwrap(), pristine);
        let dest = dir.join("estratti");
        fs::create_dir_all(&dest).unwrap();
        unpack_file(&out, &sec, Some(&trusted), &dest).unwrap();
        compare_extracted(&dest, &files);
    }

    #[test]
    fn recovery_archivio_troncato() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let pristine = fs::read(&axc).unwrap();
        let rec = dir.join("a.axc.rec");
        protect(&axc, &rec, 10).unwrap();

        // copia interrotta: mancano gli ultimi 1000 byte
        fs::write(&axc, &pristine[..pristine.len() - 1000]).unwrap();
        let out = dir.join("riparato.axc");
        repair(&axc, &rec, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), pristine);
    }

    #[test]
    fn recovery_rec_v1_rifiutato() {
        let dir = tmpdir();
        let sec = secret("pw", Some(make_keyfile(32)));
        let (axc, _t, _f, _s) = pack_sample(&dir, &sec);
        let rec = dir.join("vecchio.rec");
        let mut fake = b"AXCREC1\0".to_vec();
        fake.extend_from_slice(&[0u8; 64]);
        fs::write(&rec, &fake).unwrap();
        assert!(matches!(
            repair(&axc, &rec, &dir.join("x.axc")),
            Err(AxError::RecoveryBadMagic)
        ));
    }

    #[test]
    fn file_grande_un_solo_file() {
        // un singolo file da ~30 MB: verifica il percorso a streaming e la
        // ricostruzione via tabella offset.
        let dir = tmpdir();
        let src = dir.join("big");
        fs::create_dir_all(&src).unwrap();
        let mut data = vec![0u8; 30 * 1024 * 1024];
        rand::rngs::OsRng.fill_bytes(&mut data);
        // inserisco una porzione ripetuta per avere un po' di dedup interna
        for i in 0..data.len() / 2 {
            data[i] = (i % 251) as u8;
        }
        let p = src.join("grande.dat");
        fs::write(&p, &data).unwrap();
        let files = vec![InputFile {
            rel_path: "grande.dat".into(),
            abs_path: p,
            mode: 0,
        }];
        let sec = secret("pw-big", Some(make_keyfile(32)));
        let sk = identity::generate();
        let trusted = sk.verifying_key().to_bytes();
        let axc = dir.join("big.axc");
        let stats = pack_to_file(
            &files,
            &axc,
            &sec,
            &sk,
            compress::DEFAULT_LEVEL,
            &ArgonParams::fast(),
        )
        .unwrap();
        assert_eq!(stats.orig_size, data.len() as u64);
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        unpack_file(&axc, &sec, Some(&trusted), &out).unwrap();
        let restored = fs::read(out.join("grande.dat")).unwrap();
        assert_eq!(restored, data, "il file grande deve tornare identico");
    }
}
