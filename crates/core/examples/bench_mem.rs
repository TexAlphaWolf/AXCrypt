// Misura memoria: pack a streaming con Argon LEGGERO (per isolare il percorso
// dati). Uso: bench_mem <input_dir> <output.axc>
use axcrypt_core as ax;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);
    let mut files = Vec::new();
    for e in std::fs::read_dir(&input).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            files.push(ax::InputFile {
                rel_path: p.file_name().unwrap().to_string_lossy().into(),
                abs_path: p.clone(),
                mode: 0,
            });
        }
    }
    let sec = ax::Secret::new(b"bench".to_vec(), Some(ax::make_keyfile(32)));
    let sk = ax::identity::generate();
    let stats = ax::pack_to_file(&files, &output, &sec, &sk, 3, &ax::ArgonParams::fast()).unwrap();
    println!(
        "orig={} archive={} chunks={}",
        stats.orig_size, stats.archive_size, stats.chunk_count
    );
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM") {
            println!("{}", line);
        }
    }
}

// (nota: VmHWM = picco di RAM residente del processo)
