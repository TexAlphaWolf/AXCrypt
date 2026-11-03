//! Test del formato v4 e della compatibilità con la v3.
//!
//! La fixture `tests/fixtures/v3_sample_axc.bin` è un archivio **vero**
//! creato dalla 0.5.2 (ultima versione con bincode); `v2_sample_rec.bin` è il
//! suo recovery record. I contenuti sorgente si rigenerano qui in modo
//! deterministico per confrontarli byte per byte.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use rand::{Rng, RngCore};

use crate::format::{self, FileTime, FORMAT_V3, FORMAT_VERSION};
use crate::*;

const FIXTURE_PUBKEY: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn tmpdir() -> PathBuf {
    let mut n = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut n);
    let p = std::env::temp_dir().join(format!("axcompat-{}", u64::from_le_bytes(n)));
    fs::create_dir_all(&p).unwrap();
    p
}

fn v3_secret() -> Secret {
    Secret::new(b"fixture-v3".to_vec(), Some(vec![7u8; 32]))
}

fn fixture_pubkey() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&FIXTURE_PUBKEY[2 * i..2 * i + 2], 16).unwrap();
    }
    k
}

/// Contenuti attesi della fixture v3 (stessa ricetta del generatore).
fn v3_expected() -> Vec<(&'static str, Vec<u8>)> {
    let testo = "riga v3 ripetuta ".repeat(20000).into_bytes();
    let mut bin = vec![0u8; 100_000];
    blake3::Hasher::new()
        .update(b"axcrypt-fixture-v3")
        .finalize_xof()
        .fill(&mut bin);
    vec![
        ("testo.txt", testo.clone()),
        ("dup.txt", testo),
        ("dati.bin", bin),
        ("vuoto.dat", Vec::new()),
        ("sub/nota.txt", "nota àèìòù €".as_bytes().to_vec()),
    ]
}

fn check_v3_extract(archive: &Path, sec: &Secret) {
    let out = tmpdir();
    let written = unpack_file(archive, sec, Some(&fixture_pubkey()), &out).unwrap();
    assert_eq!(written.len(), 5);
    for (rel, data) in v3_expected() {
        assert_eq!(fs::read(out.join(rel)).unwrap(), data, "{rel}");
    }
}

// ---------------------------------------------------------------------
// Compatibilità v3
// ---------------------------------------------------------------------

#[test]
fn v3_fixture_si_legge_e_si_estrae() {
    let a = fixture("v3_sample_axc.bin");
    let core = verify_signature_file(&a, Some(&fixture_pubkey())).unwrap();
    assert_eq!(core.format_version, FORMAT_V3);

    let info = read_index_file(&a, &v3_secret(), None).unwrap();
    assert_eq!(info.header.format_version, FORMAT_V3);
    assert_eq!(info.index.entries.len(), 5);
    assert!(info.index.entries.iter().all(|e| e.mtime.is_none()));
    assert_eq!(info.index.entries[4].path, "sub/nota.txt");
    assert_eq!(info.slots_used, 1);
    // testo e dup condividono i blocchi (dedup)
    assert_eq!(info.index.entries[0].chunks, info.index.entries[1].chunks);

    check_v3_extract(&a, &v3_secret());
}

#[test]
fn v3_password_errata_rifiutata() {
    let a = fixture("v3_sample_axc.bin");
    let bad = Secret::new(b"sbagliata".to_vec(), Some(vec![7u8; 32]));
    assert!(matches!(
        read_index_file(&a, &bad, None),
        Err(AxError::NoMatchingSlot)
    ));
    let no_kf = Secret::new(b"fixture-v3".to_vec(), None);
    assert!(read_index_file(&a, &no_kf, None).is_err());
}

#[test]
fn v3_gestione_chiavi_resta_v3_e_firmato() {
    let dir = tmpdir();
    let a = dir.join("copia_v3.axc");
    fs::copy(fixture("v3_sample_axc.bin"), &a).unwrap();
    let fast = ArgonParams::fast();

    let nuova = Secret::new(b"nuova-password".to_vec(), Some(vec![7u8; 32]));
    changepw(&a, &v3_secret(), &nuova, &fast).unwrap();
    assert!(read_index_file(&a, &v3_secret(), None).is_err());

    let extra = Secret::new(b"seconda".to_vec(), None);
    addkey(&a, &nuova, &extra, &fast).unwrap();
    assert_eq!(read_index_file(&a, &extra, None).unwrap().slots_used, 2);
    rmkey(&a, &extra, &nuova).unwrap();

    // resta un archivio v3, firma ancora valida, dati intatti
    assert_eq!(&fs::read(&a).unwrap()[..8], &format::MAGIC_V3);
    verify_signature_file(&a, Some(&fixture_pubkey())).unwrap();
    check_v3_extract(&a, &extra);
}

#[test]
fn rec_v2_esistente_ripara_archivio_v3() {
    let dir = tmpdir();
    let a = dir.join("danneggiato.axc");
    let orig = fs::read(fixture("v3_sample_axc.bin")).unwrap();
    let mut bad = orig.clone();
    for i in (2000..2600).step_by(7) {
        bad[i] ^= 0x5A;
    }
    fs::write(&a, &bad).unwrap();
    let fixed = dir.join("riparato.axc");
    let rep = repair(&a, &fixture("v2_sample_rec.bin"), &fixed).unwrap();
    assert!(rep.repaired > 0);
    assert_eq!(fs::read(&fixed).unwrap(), orig);
}

#[test]
fn protect_produce_lo_stesso_rec_di_prima() {
    // Il .rec è deterministico: rigenerarlo senza bincode deve dare byte
    // identici a quello creato con bincode dalla 0.5.2.
    let dir = tmpdir();
    let rec = dir.join("nuovo.rec");
    protect(&fixture("v3_sample_axc.bin"), &rec, 10).unwrap();
    assert_eq!(
        fs::read(&rec).unwrap(),
        fs::read(fixture("v2_sample_rec.bin")).unwrap()
    );
}

// ---------------------------------------------------------------------
// Formato v4
// ---------------------------------------------------------------------

/// (percorso relativo, contenuto, data di modifica)
type Item = (String, Vec<u8>, FileTime);

/// Crea un piccolo archivio v4 con date di modifica note.
fn pack_v4(dir: &Path) -> (PathBuf, Secret, [u8; 32], Vec<Item>) {
    let src = dir.join("src");
    fs::create_dir_all(src.join("a/b")).unwrap();
    let mut rnd = vec![0u8; 70_000];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let items: Vec<Item> = vec![
        (
            "uno.txt".into(),
            "ciao v4 ".repeat(5000).into_bytes(),
            FileTime {
                secs: 981_173_106, // 2001-02-03
                nanos: 0,
            },
        ),
        (
            "a/b/rnd.bin".into(),
            rnd,
            FileTime {
                secs: 1_700_000_000,
                nanos: 123_456_789,
            },
        ),
        (
            "a/vuoto".into(),
            Vec::new(),
            FileTime {
                secs: 1_234_567_890,
                nanos: 0,
            },
        ),
    ];
    let mut inputs = Vec::new();
    for (rel, data, t) in &items {
        let p = src.join(rel);
        fs::write(&p, data).unwrap();
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(t.to_system().unwrap()).unwrap();
        inputs.push(InputFile {
            rel_path: rel.clone(),
            abs_path: p,
            mode: 0o644,
        });
    }
    let sec = Secret::new(b"pw-v4".to_vec(), Some(make_keyfile(32)));
    let sk = identity::generate();
    let a = dir.join("nuovo.axc");
    pack_to_file(&inputs, &a, &sec, &sk, 3, &ArgonParams::fast()).unwrap();
    (a, sec, sk.verifying_key().to_bytes(), items)
}

#[test]
fn v4_magic_versione_e_date_di_modifica() {
    let dir = tmpdir();
    let (a, sec, pk, items) = pack_v4(&dir);
    assert_eq!(&fs::read(&a).unwrap()[..8], b"AXCRYPT4");

    let info = read_index_file(&a, &sec, Some(&pk)).unwrap();
    assert_eq!(info.header.format_version, FORMAT_VERSION);
    for (e, (rel, _, t)) in info.index.entries.iter().zip(&items) {
        assert_eq!(&e.path, rel);
        assert_eq!(e.mtime, Some(*t));
    }

    let out = dir.join("out");
    unpack_file(&a, &sec, Some(&pk), &out).unwrap();
    for (rel, data, t) in &items {
        let p = out.join(rel);
        assert_eq!(&fs::read(&p).unwrap(), data);
        let got = fs::metadata(&p).unwrap().modified().unwrap();
        let want = t.to_system().unwrap();
        // tolleranza per filesystem a risoluzione grossolana
        let diff = got.duration_since(want).unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_secs(2), "{rel}: {diff:?}");
    }
}

#[test]
fn filetime_prima_e_dopo_il_1970() {
    for (secs, nanos) in [
        (0, 0),
        (1, 5),
        (-1, 0),
        (-1, 999_999_999),
        (-86_400 * 365, 250),
    ] {
        let t = FileTime { secs, nanos };
        let sys = t.to_system().unwrap();
        assert_eq!(FileTime::from_system(sys), Some(t));
    }
    assert!(FileTime {
        secs: 0,
        nanos: 1_000_000_000
    }
    .to_system()
    .is_none());
    assert_eq!(
        FileTime::from_system(UNIX_EPOCH + Duration::new(10, 7)),
        Some(FileTime { secs: 10, nanos: 7 })
    );
}

#[test]
fn indice_v4_piu_piccolo_del_v3() {
    // stessa struttura: v4 (u32 + zstd) contro layout v3 (u64, non compresso)
    let entries: Vec<format::FileEntry> = (0..500)
        .map(|i| format::FileEntry {
            path: format!("cartella/sottocartella/documento_{i:04}.txt"),
            size: 1000 + i,
            mode: 0o644,
            mtime: None,
            chunks: vec![i, i + 1],
            blake3: [i as u8; 32],
        })
        .collect();
    let idx = format::IndexPlaintext {
        entries,
        chunk_offsets: (0..501).map(|i| 1000 + i * 4096).collect(),
    };
    let v4 = idx.encode_v4(9).unwrap();
    let back = format::IndexPlaintext::decode(&v4, FORMAT_VERSION).unwrap();
    assert_eq!(back.entries.len(), 500);
    assert_eq!(back.entries[123].path, idx.entries[123].path);
    assert_eq!(back.chunk_offsets, idx.chunk_offsets);

    let v3_len: usize = 8
        + idx
            .entries
            .iter()
            .map(|e| 8 + e.path.len() + 8 + 4 + 8 + 8 * e.chunks.len() + 32)
            .sum::<usize>()
        + 8
        + 8 * idx.chunk_offsets.len();
    assert!(v4.len() < v3_len / 2, "v4={} v3={}", v4.len(), v3_len);
}

// ---------------------------------------------------------------------
// Robustezza: qualunque modifica o troncamento deve dare un errore pulito
// ---------------------------------------------------------------------

fn tutte_le_letture_falliscono(a: &Path, sec: &Secret, pk: &[u8; 32], out: &Path) -> bool {
    read_index_file(a, sec, Some(pk)).is_err() && unpack_file(a, sec, Some(pk), out).is_err()
}

#[test]
fn ogni_byte_alterato_viene_rilevato() {
    let dir = tmpdir();
    let (a, sec, pk, _) = pack_v4(&dir);
    let orig = fs::read(&a).unwrap();
    let probe = dir.join("probe.axc");
    let out = dir.join("out");
    let mut rng = rand::rngs::OsRng;

    // Posizioni: inizio/fine di ogni zona + campioni casuali su tutto il file.
    let n = orig.len();
    let mut pos: Vec<usize> = (0..140).chain(n - 140..n).collect();
    pos.extend((0..250).map(|_| rng.gen_range(0..n)));
    for p in pos {
        let mut b = orig.clone();
        b[p] ^= 1 << rng.gen_range(0..8);
        fs::write(&probe, &b).unwrap();
        assert!(
            tutte_le_letture_falliscono(&probe, &sec, &pk, &out),
            "modifica al byte {p} non rilevata"
        );
    }
}

#[test]
fn ogni_troncamento_viene_rilevato() {
    let dir = tmpdir();
    let (a, sec, pk, _) = pack_v4(&dir);
    let orig = fs::read(&a).unwrap();
    let probe = dir.join("probe.axc");
    let out = dir.join("out");
    let n = orig.len();
    let mut lens: Vec<usize> = (0..200).chain(n - 200..n).collect();
    lens.extend((1..40).map(|k| n * k / 40));
    for l in lens {
        fs::write(&probe, &orig[..l]).unwrap();
        assert!(
            tutte_le_letture_falliscono(&probe, &sec, &pk, &out),
            "troncamento a {l} byte non rilevato"
        );
    }
}

#[test]
fn header_e_footer_malformati_non_allocano_ne_vanno_in_panico() {
    let dir = tmpdir();
    let (a, sec, pk, _) = pack_v4(&dir);
    let orig = fs::read(&a).unwrap();
    let probe = dir.join("probe.axc");
    let out = dir.join("out");
    let n = orig.len();

    let casi: Vec<(usize, [u8; 4])> = vec![
        (8, u32::MAX.to_le_bytes()),          // lunghezza header enorme
        (8, 0u32.to_le_bytes()),              // lunghezza header nulla
        (n - 64 - 8, u32::MAX.to_le_bytes()), // lunghezza footer enorme
        (n - 64 - 8, 0u32.to_le_bytes()),
    ];
    for (off, val) in casi {
        let mut b = orig.clone();
        b[off..off + 4].copy_from_slice(&val);
        fs::write(&probe, &b).unwrap();
        assert!(tutte_le_letture_falliscono(&probe, &sec, &pk, &out));
    }

    // magic di una versione futura
    let mut b = orig.clone();
    b[..8].copy_from_slice(b"AXCRYPT5");
    fs::write(&probe, &b).unwrap();
    assert!(matches!(
        verify_signature_file(&probe, None),
        Err(AxError::BadMagic)
    ));

    // magic v3 su un corpo v4 (versione incoerente)
    let mut b = orig;
    b[..8].copy_from_slice(&format::MAGIC_V3);
    fs::write(&probe, &b).unwrap();
    assert!(matches!(
        verify_signature_file(&probe, None),
        Err(AxError::BadMagic)
    ));
}

#[test]
fn indice_malformato_rifiutato_dal_decoder() {
    // il decoder dell'indice da solo (dopo la decifratura) su dati casuali
    let mut rng = rand::rngs::OsRng;
    for _ in 0..2000 {
        let len = rng.gen_range(0..200);
        let mut b = vec![0u8; len];
        rng.fill_bytes(&mut b);
        for v in [FORMAT_V3, FORMAT_VERSION] {
            let _ = format::IndexPlaintext::decode(&b, v); // non deve andare in panico
        }
    }
    // lunghezza dichiarata enorme con pochi byte
    let mut b = vec![compress::RAW];
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(format::IndexPlaintext::decode(&b, FORMAT_VERSION).is_err());
    assert!(format::IndexPlaintext::decode(&u64::MAX.to_le_bytes(), FORMAT_V3).is_err());
}

#[test]
fn parametri_argon_alterati_non_esauriscono_la_memoria() {
    // Slot 0 inizia subito dopo l'header: [used u8][mem_kib u32][iters u32][lanes u8]...
    let dir = tmpdir();
    let (a, sec, pk, _) = pack_v4(&dir);
    let orig = fs::read(&a).unwrap();
    let slot0 = 8 + 4 + format::HEADER_BODY_LEN;
    let probe = dir.join("probe.axc");
    let casi: [(usize, &[u8]); 4] = [
        (slot0 + 1, &u32::MAX.to_le_bytes()), // ~4 TiB di RAM
        (slot0 + 5, &u32::MAX.to_le_bytes()), // 4 miliardi di iterazioni
        (slot0 + 9, &[0]),                    // 0 lane
        (slot0 + 9, &[255]),                  // 255 lane
    ];
    for (off, val) in casi {
        let mut b = orig.clone();
        b[off..off + val.len()].copy_from_slice(val);
        fs::write(&probe, &b).unwrap();
        let t = std::time::Instant::now();
        assert!(matches!(
            read_index_file(&probe, &sec, Some(&pk)),
            Err(AxError::NoMatchingSlot)
        ));
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    // e non si possono nemmeno creare slot fuori limite
    let troppo = ArgonParams {
        mem_kib: format::MAX_ARGON_MEM_KIB + 1,
        iters: 1,
        lanes: 1,
    };
    let other = Secret::new(b"x".to_vec(), None);
    assert!(matches!(
        addkey(&a, &sec, &other, &troppo),
        Err(AxError::Kdf(_))
    ));
}
