//! CLI di AXCrypt: keygen, makekeyfile, pack, unpack, list, info.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use walkdir::WalkDir;

use axcrypt_core as ax;

#[derive(Parser)]
#[command(name = "axcrypt", version, about = "Archiviatore compresso e cifrato")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Genera una coppia di chiavi di firma (identità) e il file .pub.
    Keygen {
        /// Percorso del file identità da creare (es. I:\chiavi\identity.axid)
        #[arg(long)]
        out: PathBuf,
    },
    /// Crea un keyfile casuale da 256 bit (da tenere sulla USB).
    Makekeyfile {
        #[arg(long)]
        out: PathBuf,
        /// Lunghezza in byte (default 32 = 256 bit).
        #[arg(long, default_value_t = 32)]
        len: usize,
    },
    /// Comprime, cifra e firma una cartella o un file.
    Pack {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Livello zstd (1-22, default 9).
        #[arg(long, default_value_t = 9)]
        level: i32,
    },
    /// Estrae un archivio (verifica firma, poi decifra).
    Unpack {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// File .pub della chiave fidata: accetta solo archivi firmati da essa.
        #[arg(long)]
        trust: Option<PathBuf>,
    },
    /// Elenca i file contenuti (richiede password + keyfile).
    List {
        input: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        trust: Option<PathBuf>,
    },
    /// Mostra informazioni sull'archivio (header, dimensioni, dedup).
    Info {
        input: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        trust: Option<PathBuf>,
    },
    /// Cambia la password (ed eventualmente il keyfile) di un archivio.
    Changepw {
        input: PathBuf,
        /// Keyfile attuale.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Nuovo keyfile (se vuoi cambiarlo; altrimenti resta quello attuale).
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
    },
    /// Aggiunge una seconda chiave d'accesso (password/keyfile) all'archivio.
    Addkey {
        input: PathBuf,
        /// Keyfile di una chiave già valida (autorizza l'aggiunta).
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Keyfile della nuova chiave (default: lo stesso attuale).
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
    },
    /// Rimuove una chiave d'accesso. Richiede una chiave valida che autorizzi.
    Rmkey {
        input: PathBuf,
        /// Keyfile di una chiave valida che autorizza l'operazione.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Keyfile della chiave DA RIMUOVERE (default: lo stesso autorizzante).
        #[arg(long)]
        target_keyfile: Option<PathBuf>,
    },
    /// Crea un file di recupero (.rec) con parità Reed-Solomon.
    Protect {
        input: PathBuf,
        /// File .rec da creare (default: <input>.rec).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Ridondanza percentuale (1-100, default 10).
        #[arg(long, default_value_t = 10)]
        redundancy: u32,
    },
    /// Ripara un archivio danneggiato usando il file di recupero.
    Repair {
        input: PathBuf,
        /// File .rec (default: <input>.rec).
        #[arg(long)]
        rec: Option<PathBuf>,
        /// File riparato da scrivere (default: <input>.repaired).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("Errore: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => keygen(&out),
        Cmd::Makekeyfile { out, len } => makekeyfile(&out, len),
        Cmd::Pack {
            identity,
            keyfile,
            input,
            output,
            level,
        } => pack(&identity, keyfile.as_deref(), &input, &output, level),
        Cmd::Unpack {
            input,
            output,
            keyfile,
            trust,
        } => unpack(&input, &output, keyfile.as_deref(), trust.as_deref()),
        Cmd::List {
            input,
            keyfile,
            trust,
        } => list(&input, keyfile.as_deref(), trust.as_deref()),
        Cmd::Info {
            input,
            keyfile,
            trust,
        } => info(&input, keyfile.as_deref(), trust.as_deref()),
        Cmd::Changepw {
            input,
            keyfile,
            new_keyfile,
        } => changepw(&input, keyfile.as_deref(), new_keyfile.as_deref()),
        Cmd::Addkey {
            input,
            keyfile,
            new_keyfile,
        } => addkey(&input, keyfile.as_deref(), new_keyfile.as_deref()),
        Cmd::Rmkey {
            input,
            keyfile,
            target_keyfile,
        } => rmkey(&input, keyfile.as_deref(), target_keyfile.as_deref()),
        Cmd::Protect {
            input,
            out,
            redundancy,
        } => protect(&input, out.as_deref(), redundancy),
        Cmd::Repair { input, rec, out } => repair(&input, rec.as_deref(), out.as_deref()),
    }
}

fn protect(input: &Path, out: Option<&Path>, redundancy: u32) -> Result<()> {
    let out_path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| append_ext(input, "rec"));
    let stats = ax::protect(input, &out_path, redundancy)?;
    println!(
        "Recovery record creato: {} ({} blocchi dati + {} di parità, blocco {} byte, overhead {} byte)",
        out_path.display(),
        stats.data_count,
        stats.parity_count,
        stats.block_size,
        stats.overhead_bytes
    );
    println!("Tollera fino a {} blocchi danneggiati.", stats.parity_count);
    Ok(())
}

fn repair(input: &Path, rec: Option<&Path>, out: Option<&Path>) -> Result<()> {
    let rec_path = rec
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| append_ext(input, "rec"));
    let out_path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| append_ext(input, "repaired"));
    let report = ax::repair(input, &rec_path, &out_path)?;
    if report.already_ok {
        println!("Archivio già integro: nessuna riparazione necessaria.");
    } else {
        println!(
            "Riparati {} blocchi su {} (parità {}). Risultato: {}",
            report.repaired,
            report.data_count,
            report.parity_count,
            out_path.display()
        );
    }
    Ok(())
}

fn keygen(out: &Path) -> Result<()> {
    let sk = ax::identity::generate();
    ax::identity::save_identity(out, &sk).context("salvataggio identità")?;
    let pub_path = append_ext(out, "pub");
    ax::identity::save_public(&pub_path, &sk.verifying_key())
        .context("salvataggio chiave pubblica")?;
    println!("Identità creata:");
    println!("  privata : {}", out.display());
    println!("  pubblica: {}", pub_path.display());
    println!("Conserva il file privato come un segreto (es. sulla USB).");
    Ok(())
}

fn makekeyfile(out: &Path, len: usize) -> Result<()> {
    if len < 16 {
        bail!("keyfile troppo corto: usa almeno 16 byte (consigliati 32)");
    }
    let kf = ax::make_keyfile(len);
    fs::write(out, &kf).context("scrittura keyfile")?;
    println!("Keyfile da {} byte creato: {}", len, out.display());
    println!("Tienilo sulla chiavetta USB: senza di esso l'archivio non si apre.");
    Ok(())
}

fn pack(
    identity: &Path,
    keyfile: Option<&Path>,
    input: &Path,
    output: &Path,
    level: i32,
) -> Result<()> {
    let sk = ax::identity::load_identity(identity).context("caricamento identità")?;
    let kf = read_keyfile(keyfile)?;
    let password = prompt_password_confirm()?;
    let secret = ax::Secret::new(password.into_bytes(), kf);

    let files = collect_files(input)?;
    if files.is_empty() {
        bail!("nessun file da archiviare in {}", input.display());
    }
    println!("Archiviazione di {} file...", files.len());

    let stats = ax::pack_to_file(
        &files,
        output,
        &secret,
        &sk,
        level,
        &ax::ArgonParams::strong(),
    )?;
    report_ratio(stats.orig_size, stats.archive_size);
    println!(
        "Archivio creato: {} ({} blocchi unici)",
        output.display(),
        stats.chunk_count
    );
    Ok(())
}

fn unpack(input: &Path, output: &Path, keyfile: Option<&Path>, trust: Option<&Path>) -> Result<()> {
    let trusted = load_trust(trust)?;
    let kf = read_keyfile(keyfile)?;
    let password = rpassword::prompt_password("Password: ").context("lettura password")?;
    let secret = ax::Secret::new(password.into_bytes(), kf);

    fs::create_dir_all(output).context("creazione cartella di output")?;
    let written = ax::unpack_file(input, &secret, trusted.as_ref(), output)?;
    println!("Estratti {} file in {}", written.len(), output.display());
    Ok(())
}

fn list(input: &Path, keyfile: Option<&Path>, trust: Option<&Path>) -> Result<()> {
    let info = open_info(input, keyfile, trust)?;
    println!("{:<50} {:>14}", "PERCORSO", "DIMENSIONE");
    for e in &info.index.entries {
        println!("{:<50} {:>14}", e.path, e.size);
    }
    println!("Totale: {} file", info.index.entries.len());
    Ok(())
}

fn info(input: &Path, keyfile: Option<&Path>, trust: Option<&Path>) -> Result<()> {
    let archive_len = fs::metadata(input).map(|m| m.len()).unwrap_or(0);
    let info = open_info(input, keyfile, trust)?;
    println!("Formato versione : {}", info.header.format_version);
    println!("Firmato da       : {}", hex(&info.header.signer_pubkey));
    println!(
        "Argon2id (slot)  : {} KiB, {} iter, {} lanes",
        info.argon_mem_kib, info.argon_iters, info.argon_lanes
    );
    println!("Chiavi d'accesso : {}", info.slots_used);
    println!("Blocchi unici    : {}", info.footer.chunk_count);
    println!("File             : {}", info.index.entries.len());
    report_ratio(info.footer.total_orig_size, archive_len);
    Ok(())
}

fn changepw(input: &Path, keyfile: Option<&Path>, new_keyfile: Option<&Path>) -> Result<()> {
    let kf = read_keyfile(keyfile)?;
    let new_kf = match new_keyfile {
        Some(p) => Some(fs::read(p).context("lettura nuovo keyfile")?),
        None => kf.clone(),
    };
    let old_pw = rpassword::prompt_password("Password attuale: ").context("lettura password")?;
    let new_pw = prompt_password_confirm_label("Nuova password")?;
    let old = ax::Secret::new(old_pw.into_bytes(), kf);
    let new = ax::Secret::new(new_pw.into_bytes(), new_kf);
    ax::changepw(input, &old, &new, &ax::ArgonParams::strong())?;
    println!("Password aggiornata (dati non ricompressi).");
    Ok(())
}

fn addkey(input: &Path, keyfile: Option<&Path>, new_keyfile: Option<&Path>) -> Result<()> {
    let kf = read_keyfile(keyfile)?;
    let new_kf = match new_keyfile {
        Some(p) => Some(fs::read(p).context("lettura nuovo keyfile")?),
        None => kf.clone(),
    };
    let existing_pw = rpassword::prompt_password("Password di una chiave valida: ")?;
    let new_pw = prompt_password_confirm_label("Password della nuova chiave")?;
    let existing = ax::Secret::new(existing_pw.into_bytes(), kf);
    let newsec = ax::Secret::new(new_pw.into_bytes(), new_kf);
    ax::addkey(input, &existing, &newsec, &ax::ArgonParams::strong())?;
    println!("Nuova chiave d'accesso aggiunta.");
    Ok(())
}

fn rmkey(input: &Path, keyfile: Option<&Path>, target_keyfile: Option<&Path>) -> Result<()> {
    let kf = read_keyfile(keyfile)?;
    let target_kf = match target_keyfile {
        Some(p) => Some(fs::read(p).context("lettura keyfile della chiave da rimuovere")?),
        None => kf.clone(),
    };
    let auth_pw = rpassword::prompt_password("Password autorizzante: ")?;
    let target_pw = rpassword::prompt_password("Password della chiave DA RIMUOVERE: ")?;
    let existing = ax::Secret::new(auth_pw.into_bytes(), kf);
    let target = ax::Secret::new(target_pw.into_bytes(), target_kf);
    ax::rmkey(input, &existing, &target)?;
    println!("Chiave d'accesso rimossa.");
    Ok(())
}

// ---- helper ----

fn open_info(
    input: &Path,
    keyfile: Option<&Path>,
    trust: Option<&Path>,
) -> Result<ax::ArchiveInfo> {
    let trusted = load_trust(trust)?;
    let kf = read_keyfile(keyfile)?;
    let password = rpassword::prompt_password("Password: ").context("lettura password")?;
    let secret = ax::Secret::new(password.into_bytes(), kf);
    Ok(ax::read_index_file(input, &secret, trusted.as_ref())?)
}

fn collect_files(input: &Path) -> Result<Vec<ax::InputFile>> {
    let mut out = Vec::new();
    if input.is_file() {
        let name = input.file_name().unwrap().to_string_lossy().to_string();
        out.push(ax::InputFile {
            rel_path: name,
            abs_path: input.to_path_buf(),
            mode: 0,
        });
        return Ok(out);
    }
    let base = input;
    for entry in WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(base).unwrap_or(entry.path());
            let rel_path = rel.to_string_lossy().replace('\\', "/");
            out.push(ax::InputFile {
                rel_path,
                abs_path: entry.path().to_path_buf(),
                mode: 0,
            });
        }
    }
    Ok(out)
}

fn read_keyfile(path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(p) => {
            Ok(Some(fs::read(p).with_context(|| {
                format!("lettura keyfile {}", p.display())
            })?))
        }
        None => Ok(None),
    }
}

fn load_trust(path: Option<&Path>) -> Result<Option<[u8; 32]>> {
    match path {
        Some(p) => Ok(Some(
            ax::identity::load_public(p).context("lettura chiave fidata")?,
        )),
        None => Ok(None),
    }
}

fn prompt_password_confirm() -> Result<String> {
    prompt_password_confirm_label("Password")
}

fn prompt_password_confirm_label(label: &str) -> Result<String> {
    let p1 = rpassword::prompt_password(format!("{label}: ")).context("lettura password")?;
    let p2 = rpassword::prompt_password(format!("Conferma {}: ", label.to_lowercase()))
        .context("lettura password")?;
    if p1 != p2 {
        bail!("le password non coincidono");
    }
    if p1.len() < 8 {
        eprintln!("Attenzione: password corta. Usa una passphrase lunga + il keyfile.");
    }
    Ok(p1)
}

fn report_ratio(orig: u64, archive: u64) {
    if orig == 0 {
        return;
    }
    let ratio = archive as f64 / orig as f64 * 100.0;
    println!(
        "Originale: {} byte  →  Archivio: {} byte  ({:.1}% dell'originale)",
        orig, archive, ratio
    );
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
