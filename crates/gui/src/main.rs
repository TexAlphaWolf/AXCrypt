//! GUI di AXCrypt (egui/eframe). Riusa interamente `axcrypt_core`.
//!
//! Tema scuro (nero/grigi) con accenti arancioni, card con ombra, generatore di
//! password integrato e misuratore di robustezza. Le operazioni lunghe girano
//! su un thread in background; l'interfaccia resta reattiva.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use axcrypt_core as ax;
use eframe::egui::{self, Color32, Rounding, Stroke};
use walkdir::WalkDir;

// ---- palette ----
const BG: Color32 = Color32::from_rgb(14, 14, 15);
const PANEL: Color32 = Color32::from_rgb(26, 26, 28);
const CARD: Color32 = Color32::from_rgb(23, 23, 26);
const WIDGET: Color32 = Color32::from_rgb(38, 38, 42);
const WIDGET_HOVER: Color32 = Color32::from_rgb(52, 52, 58);
const FIELD_BG: Color32 = Color32::from_rgb(12, 12, 13);
const TEXT: Color32 = Color32::from_rgb(222, 222, 226);
const TEXT_DIM: Color32 = Color32::from_rgb(150, 150, 156);
const ORANGE: Color32 = Color32::from_rgb(255, 138, 24);
const ORANGE_DIM: Color32 = Color32::from_rgb(200, 94, 16);
const BORDER: Color32 = Color32::from_rgb(58, 58, 64);
const RED: Color32 = Color32::from_rgb(230, 90, 80);
const AMBER: Color32 = Color32::from_rgb(230, 170, 60);
const GREEN: Color32 = Color32::from_rgb(120, 200, 120);

const LABEL_W: f32 = 150.0;
const FIELD_W: f32 = 320.0;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 640.0])
            .with_min_inner_size([640.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "AXCrypt",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::<App>::default())
        }),
    )
}

fn apply_theme(ctx: &egui::Context) {
    use egui::{FontFamily::Proportional, FontId, TextStyle};
    let mut style = (*ctx.style()).clone();
    let mut v = egui::Visuals::dark();

    v.override_text_color = Some(TEXT);
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = FIELD_BG;
    v.faint_bg_color = CARD;
    v.hyperlink_color = ORANGE;
    v.selection.bg_fill = ORANGE_DIM;
    v.selection.stroke = Stroke::new(1.0_f32, ORANGE);

    let rnd = Rounding::same(6.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.rounding = rnd;
    }
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.inactive.bg_fill = WIDGET;
    v.widgets.inactive.weak_bg_fill = WIDGET;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.hovered.bg_fill = WIDGET_HOVER;
    v.widgets.hovered.weak_bg_fill = WIDGET_HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.5_f32, ORANGE);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.widgets.active.bg_fill = ORANGE_DIM;
    v.widgets.active.weak_bg_fill = ORANGE_DIM;
    v.widgets.active.bg_stroke = Stroke::new(1.5_f32, ORANGE);
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(20, 20, 20));
    v.widgets.open.bg_fill = WIDGET;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, ORANGE);

    v.window_rounding = Rounding::same(8.0);
    v.window_stroke = Stroke::new(1.0_f32, BORDER);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size.y = 28.0;
    style.text_styles = [
        (TextStyle::Heading, FontId::new(18.0, Proportional)),
        (TextStyle::Body, FontId::new(14.0, Proportional)),
        (TextStyle::Button, FontId::new(14.0, Proportional)),
        (
            TextStyle::Monospace,
            FontId::new(13.5, egui::FontFamily::Monospace),
        ),
        (TextStyle::Small, FontId::new(11.0, Proportional)),
    ]
    .into();
    ctx.set_style(style);
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Pack,
    Unpack,
    Keys,
    Recovery,
}

enum TaskMsg {
    Done(Result<String, String>),
}

/// Stato del generatore di password (isolato per evitare conflitti di borrow).
struct GenState {
    open: bool,
    len: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    value: String,
    reveal: bool,
}

impl Default for GenState {
    fn default() -> Self {
        GenState {
            open: false,
            len: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            value: String::new(),
            reveal: false,
        }
    }
}

struct App {
    tab: Tab,

    pack_input: String,
    pack_output: String,
    pack_identity: String,
    pack_keyfile: String,
    pack_pw: String,
    pack_pw2: String,
    pack_reveal: bool,
    pack_level: i32,
    pack_make_rec: bool,
    pack_redundancy: u32,
    gen: GenState,

    un_archive: String,
    un_outdir: String,
    un_keyfile: String,
    un_trust: String,
    un_pw: String,

    kg_out: String,
    mk_out: String,
    cp_archive: String,
    cp_keyfile: String,
    cp_oldpw: String,
    cp_newpw: String,
    cp_newpw2: String,
    ak_archive: String,
    ak_keyfile: String,
    ak_existpw: String,
    ak_newpw: String,
    rk_archive: String,
    rk_keyfile: String,
    rk_authpw: String,
    rk_targetpw: String,

    pr_archive: String,
    pr_redundancy: u32,
    rp_archive: String,
    rp_rec: String,
    rp_out: String,

    busy: bool,
    status: String,
    status_ok: bool,
    rx: Option<Receiver<TaskMsg>>,
}

impl Default for App {
    fn default() -> Self {
        App {
            tab: Tab::Pack,
            pack_input: String::new(),
            pack_output: String::new(),
            pack_identity: String::new(),
            pack_keyfile: String::new(),
            pack_pw: String::new(),
            pack_pw2: String::new(),
            pack_reveal: false,
            pack_level: 9,
            pack_make_rec: false,
            pack_redundancy: 10,
            gen: GenState::default(),
            un_archive: String::new(),
            un_outdir: String::new(),
            un_keyfile: String::new(),
            un_trust: String::new(),
            un_pw: String::new(),
            kg_out: String::new(),
            mk_out: String::new(),
            cp_archive: String::new(),
            cp_keyfile: String::new(),
            cp_oldpw: String::new(),
            cp_newpw: String::new(),
            cp_newpw2: String::new(),
            ak_archive: String::new(),
            ak_keyfile: String::new(),
            ak_existpw: String::new(),
            ak_newpw: String::new(),
            rk_archive: String::new(),
            rk_keyfile: String::new(),
            rk_authpw: String::new(),
            rk_targetpw: String::new(),
            pr_archive: String::new(),
            pr_redundancy: 10,
            rp_archive: String::new(),
            rp_rec: String::new(),
            rp_out: String::new(),
            busy: false,
            status: "Pronto.".into(),
            status_ok: true,
            rx: None,
        }
    }
}

// ---- helper core ----

fn load_secret(keyfile: &str, pw: &str) -> Result<ax::Secret, String> {
    let kf = if keyfile.trim().is_empty() {
        None
    } else {
        Some(fs::read(keyfile).map_err(|e| format!("keyfile: {e}"))?)
    };
    Ok(ax::Secret::new(pw.as_bytes().to_vec(), kf))
}

fn load_trust(path: &str) -> Result<Option<[u8; 32]>, String> {
    if path.trim().is_empty() {
        Ok(None)
    } else {
        ax::identity::load_public(path)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}

fn collect_files(input: &str) -> Result<Vec<ax::InputFile>, String> {
    let base = PathBuf::from(input);
    if base.is_file() {
        let name = base.file_name().unwrap().to_string_lossy().to_string();
        return Ok(vec![ax::InputFile {
            rel_path: name,
            abs_path: base,
            mode: 0,
        }]);
    }
    if !base.is_dir() {
        return Err("cartella o file di input non valido".into());
    }
    let mut out = Vec::new();
    for e in WalkDir::new(&base).into_iter().filter_map(|e| e.ok()) {
        if e.file_type().is_file() {
            let rel = e.path().strip_prefix(&base).unwrap_or(e.path());
            out.push(ax::InputFile {
                rel_path: rel.to_string_lossy().replace('\\', "/"),
                abs_path: e.path().to_path_buf(),
                mode: 0,
            });
        }
    }
    if out.is_empty() {
        return Err("nessun file da archiviare".into());
    }
    Ok(out)
}

impl App {
    fn run_task<F>(&mut self, f: F)
    where
        F: FnOnce() -> Result<String, String> + Send + 'static,
    {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        self.status = "In corso…".into();
        thread::spawn(move || {
            let _ = tx.send(TaskMsg::Done(f()));
        });
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.rx {
            if let Ok(TaskMsg::Done(res)) = rx.try_recv() {
                match res {
                    Ok(msg) => {
                        self.status = msg;
                        self.status_ok = true;
                    }
                    Err(e) => {
                        self.status = format!("Errore: {e}");
                        self.status_ok = false;
                    }
                }
                self.busy = false;
                self.rx = None;
            }
        }
    }
}

// ---- widget helper ----

enum Pick {
    File,
    Folder,
    Save,
}

fn label(ui: &mut egui::Ui, text: &str) {
    ui.add_sized(
        [LABEL_W, 22.0],
        egui::Label::new(egui::RichText::new(text).color(TEXT_DIM)),
    );
}

fn path_row(ui: &mut egui::Ui, text: &str, value: &mut String, pick: Pick) {
    ui.horizontal(|ui| {
        label(ui, text);
        ui.add(egui::TextEdit::singleline(value).desired_width(FIELD_W));
        if ui.button("Sfoglia").clicked() {
            let chosen = match pick {
                Pick::File => rfd::FileDialog::new().pick_file(),
                Pick::Folder => rfd::FileDialog::new().pick_folder(),
                Pick::Save => rfd::FileDialog::new().save_file(),
            };
            if let Some(p) = chosen {
                *value = p.display().to_string();
            }
        }
    });
}

fn pw_row(ui: &mut egui::Ui, text: &str, value: &mut String) {
    ui.horizontal(|ui| {
        label(ui, text);
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(FIELD_W),
        );
    });
}

/// Campo password con pulsante mostra/nascondi.
fn pw_row_reveal(ui: &mut egui::Ui, text: &str, value: &mut String, reveal: &mut bool) {
    ui.horizontal(|ui| {
        label(ui, text);
        ui.add(
            egui::TextEdit::singleline(value)
                .password(!*reveal)
                .desired_width(FIELD_W),
        );
        if ui
            .button(if *reveal { "Nascondi" } else { "Mostra" })
            .clicked()
        {
            *reveal = !*reveal;
        }
    });
}

/// Barra di robustezza sotto un campo password.
fn strength_bar(ui: &mut egui::Ui, pw: &str) {
    let bits = ax::estimate_entropy(pw);
    let (lbl, color) = if bits < 1.0 {
        ("—", TEXT_DIM)
    } else if bits < 50.0 {
        ("Debole", RED)
    } else if bits < 80.0 {
        ("Media", AMBER)
    } else if bits < 120.0 {
        ("Forte", GREEN)
    } else {
        ("Eccellente", GREEN)
    };
    ui.horizontal(|ui| {
        ui.add_space(LABEL_W);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(FIELD_W, 8.0), egui::Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, Rounding::same(4.0), WIDGET);
        let frac = (bits / 128.0).clamp(0.0, 1.0) as f32;
        if frac > 0.0 {
            let filled =
                egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * frac, rect.height()));
            p.rect_filled(filled, Rounding::same(4.0), color);
        }
        ui.label(
            egui::RichText::new(format!("{lbl} · {:.0} bit", bits))
                .small()
                .color(color),
        );
    });
}

/// Generatore di password. Ritorna Some(pw) quando l'utente preme "Usa".
fn password_generator(ui: &mut egui::Ui, g: &mut GenState) -> Option<String> {
    let mut chosen = None;
    ui.horizontal(|ui| {
        ui.add_space(LABEL_W);
        let txt = if g.open {
            "▾ Generatore password"
        } else {
            "▸ Generatore password"
        };
        if ui.button(egui::RichText::new(txt).color(ORANGE)).clicked() {
            g.open = !g.open;
        }
    });
    if !g.open {
        return None;
    }
    egui::Frame::none()
        .fill(FIELD_BG)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .rounding(Rounding::same(6.0))
        .inner_margin(egui::Margin::same(10.0))
        .outer_margin(egui::Margin {
            left: LABEL_W,
            bottom: 4.0,
            ..Default::default()
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Lunghezza").color(TEXT_DIM));
                ui.add(egui::Slider::new(&mut g.len, 8..=64));
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut g.lower, "a-z");
                ui.checkbox(&mut g.upper, "A-Z");
                ui.checkbox(&mut g.digits, "0-9");
                ui.checkbox(&mut g.symbols, "!@#");
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Genera").clicked() {
                    let opts = ax::PwOptions {
                        length: g.len,
                        lower: g.lower,
                        upper: g.upper,
                        digits: g.digits,
                        symbols: g.symbols,
                    };
                    g.value = ax::generate_password(&opts);
                    g.reveal = true;
                }
                if !g.value.is_empty() {
                    if ui
                        .button(if g.reveal { "Nascondi" } else { "Mostra" })
                        .clicked()
                    {
                        g.reveal = !g.reveal;
                    }
                    if ui.button("Copia").clicked() {
                        ui.output_mut(|o| o.copied_text = g.value.clone());
                    }
                    if ui.button("Usa").clicked() {
                        chosen = Some(g.value.clone());
                    }
                }
            });
            if !g.value.is_empty() {
                let shown = if g.reveal {
                    g.value.clone()
                } else {
                    "•".repeat(g.value.chars().count())
                };
                ui.add_space(2.0);
                ui.label(egui::RichText::new(shown).monospace().color(TEXT));
                let bits = ax::estimate_entropy(&g.value);
                let color = if bits < 80.0 { AMBER } else { GREEN };
                ui.label(
                    egui::RichText::new(format!("robustezza: {:.0} bit", bits))
                        .small()
                        .color(color),
                );
            }
        });
    chosen
}

/// Card con ombra, bordo arancione e titolo sottolineato.
fn card(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, ORANGE))
        .rounding(Rounding::same(8.0))
        .shadow(egui::epaint::Shadow {
            offset: egui::vec2(0.0, 3.0),
            blur: 10.0,
            spread: 0.0,
            color: Color32::from_black_alpha(90),
        })
        .inner_margin(egui::Margin::same(16.0))
        .outer_margin(egui::Margin {
            bottom: 12.0,
            ..Default::default()
        })
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).size(16.0).strong().color(ORANGE));
            let (rect, _) = ui.allocate_exact_size(egui::vec2(44.0, 3.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, Rounding::same(2.0), ORANGE);
            ui.add_space(10.0);
            body(ui);
        });
}

fn action(ui: &mut egui::Ui, text: &str) -> bool {
    let btn = egui::Button::new(
        egui::RichText::new(text)
            .strong()
            .color(Color32::from_rgb(20, 20, 20)),
    )
    .fill(ORANGE)
    .rounding(Rounding::same(6.0));
    ui.add_sized([ui.available_width().min(220.0), 32.0], btn)
        .clicked()
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.busy {
            ctx.request_repaint();
        }

        egui::SidePanel::left("side")
            .resizable(false)
            .exact_width(176.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::same(16.0)),
            )
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("AXCrypt")
                        .size(24.0)
                        .strong()
                        .color(ORANGE),
                );
                ui.label(
                    egui::RichText::new("archiviatore cifrato")
                        .size(11.0)
                        .color(TEXT_DIM),
                );
                ui.add_space(20.0);
                self.tab_button(ui, Tab::Pack, "Crea archivio");
                self.tab_button(ui, Tab::Unpack, "Estrai");
                self.tab_button(ui, Tab::Keys, "Chiavi");
                self.tab_button(ui, Tab::Recovery, "Recupero");
            });

        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(16.0, 9.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.busy {
                        ui.spinner();
                    }
                    ui.colored_label(if self.status_ok { GREEN } else { RED }, "●");
                    ui.label(&self.status);
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(18.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!self.busy, |ui| match self.tab {
                        Tab::Pack => self.ui_pack(ui),
                        Tab::Unpack => self.ui_unpack(ui),
                        Tab::Keys => self.ui_keys(ui),
                        Tab::Recovery => self.ui_recovery(ui),
                    });
                });
            });
    }
}

impl App {
    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, text: &str) {
        let selected = self.tab == tab;
        let rich = if selected {
            egui::RichText::new(text).strong().color(ORANGE)
        } else {
            egui::RichText::new(text).color(TEXT)
        };
        let btn = egui::Button::new(rich)
            .fill(if selected { CARD } else { PANEL })
            .stroke(if selected {
                Stroke::new(1.0_f32, ORANGE)
            } else {
                Stroke::NONE
            })
            .rounding(Rounding::same(6.0));
        if ui.add_sized([ui.available_width(), 34.0], btn).clicked() {
            self.tab = tab;
        }
        ui.add_space(5.0);
    }

    fn ui_pack(&mut self, ui: &mut egui::Ui) {
        card(ui, "Crea archivio", |ui| {
            path_row(ui, "Cartella/file", &mut self.pack_input, Pick::Folder);
            path_row(ui, "Archivio (.axc)", &mut self.pack_output, Pick::Save);
            path_row(ui, "Identità (.axid)", &mut self.pack_identity, Pick::File);
            path_row(ui, "Keyfile (USB)", &mut self.pack_keyfile, Pick::File);
            pw_row_reveal(ui, "Password", &mut self.pack_pw, &mut self.pack_reveal);
            strength_bar(ui, &self.pack_pw);
            pw_row(ui, "Conferma password", &mut self.pack_pw2);
            if let Some(pw) = password_generator(ui, &mut self.gen) {
                self.pack_pw = pw.clone();
                self.pack_pw2 = pw;
                self.pack_reveal = false;
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                label(ui, "Compressione");
                ui.add(egui::Slider::new(&mut self.pack_level, 1..=22).text("zstd"));
            });
            ui.horizontal(|ui| {
                ui.add_space(LABEL_W);
                ui.checkbox(&mut self.pack_make_rec, "Crea anche recovery record");
                if self.pack_make_rec {
                    ui.add(egui::Slider::new(&mut self.pack_redundancy, 1..=50).suffix("%"));
                }
            });
            ui.add_space(8.0);
            if action(ui, "Crea archivio") {
                let (input, output, identity, keyfile, pw, pw2) = (
                    self.pack_input.clone(),
                    self.pack_output.clone(),
                    self.pack_identity.clone(),
                    self.pack_keyfile.clone(),
                    self.pack_pw.clone(),
                    self.pack_pw2.clone(),
                );
                let (level, make_rec, redundancy) =
                    (self.pack_level, self.pack_make_rec, self.pack_redundancy);
                self.run_task(move || {
                    if pw != pw2 {
                        return Err("le password non coincidono".into());
                    }
                    let sk = ax::identity::load_identity(&identity).map_err(|e| e.to_string())?;
                    let secret = load_secret(&keyfile, &pw)?;
                    let files = collect_files(&input)?;
                    let outp = PathBuf::from(&output);
                    let stats = ax::pack_to_file(
                        &files,
                        &outp,
                        &secret,
                        &sk,
                        level,
                        &ax::ArgonParams::strong(),
                    )
                    .map_err(|e| e.to_string())?;
                    let mut msg = format!(
                        "Archivio creato: {} file, {} blocchi, {} → {} byte.",
                        files.len(),
                        stats.chunk_count,
                        stats.orig_size,
                        stats.archive_size
                    );
                    if make_rec {
                        let rec = PathBuf::from(format!("{output}.rec"));
                        let rs = ax::protect(&outp, &rec, redundancy).map_err(|e| e.to_string())?;
                        msg.push_str(&format!(
                            " Recovery: {} blocchi di parità.",
                            rs.parity_count
                        ));
                    }
                    Ok(msg)
                });
            }
        });
    }

    fn ui_unpack(&mut self, ui: &mut egui::Ui) {
        card(ui, "Estrai archivio", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.un_archive, Pick::File);
            path_row(ui, "Destinazione", &mut self.un_outdir, Pick::Folder);
            path_row(ui, "Keyfile (USB)", &mut self.un_keyfile, Pick::File);
            path_row(ui, "Chiave fidata (.pub)", &mut self.un_trust, Pick::File);
            pw_row(ui, "Password", &mut self.un_pw);
            ui.add_space(8.0);
            if action(ui, "Estrai") {
                let (archive, outdir, keyfile, trust, pw) = (
                    self.un_archive.clone(),
                    self.un_outdir.clone(),
                    self.un_keyfile.clone(),
                    self.un_trust.clone(),
                    self.un_pw.clone(),
                );
                self.run_task(move || {
                    let secret = load_secret(&keyfile, &pw)?;
                    let trusted = load_trust(&trust)?;
                    fs::create_dir_all(&outdir).map_err(|e| e.to_string())?;
                    let w = ax::unpack_file(
                        &PathBuf::from(&archive),
                        &secret,
                        trusted.as_ref(),
                        &PathBuf::from(&outdir),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(format!("Estratti {} file in {}", w.len(), outdir))
                });
            }
        });
    }

    fn ui_keys(&mut self, ui: &mut egui::Ui) {
        card(ui, "Genera identità di firma", |ui| {
            path_row(ui, "File (.axid)", &mut self.kg_out, Pick::Save);
            ui.add_space(8.0);
            if action(ui, "Genera identità") {
                let out = self.kg_out.clone();
                self.run_task(move || {
                    let sk = ax::identity::generate();
                    ax::identity::save_identity(&out, &sk).map_err(|e| e.to_string())?;
                    let pubp = format!("{out}.pub");
                    ax::identity::save_public(&PathBuf::from(&pubp), &sk.verifying_key())
                        .map_err(|e| e.to_string())?;
                    Ok(format!("Identità creata: {out} (+ {pubp})"))
                });
            }
        });

        card(ui, "Crea keyfile (256 bit)", |ui| {
            path_row(ui, "File keyfile", &mut self.mk_out, Pick::Save);
            ui.add_space(8.0);
            if action(ui, "Crea keyfile") {
                let out = self.mk_out.clone();
                self.run_task(move || {
                    fs::write(&out, ax::make_keyfile(32)).map_err(|e| e.to_string())?;
                    Ok(format!("Keyfile da 32 byte creato: {out}"))
                });
            }
        });

        card(ui, "Cambia password", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.cp_archive, Pick::File);
            path_row(ui, "Keyfile", &mut self.cp_keyfile, Pick::File);
            pw_row(ui, "Password attuale", &mut self.cp_oldpw);
            pw_row(ui, "Nuova password", &mut self.cp_newpw);
            strength_bar(ui, &self.cp_newpw);
            pw_row(ui, "Conferma nuova", &mut self.cp_newpw2);
            if let Some(pw) = password_generator(ui, &mut self.gen) {
                self.cp_newpw = pw.clone();
                self.cp_newpw2 = pw;
            }
            ui.add_space(8.0);
            if action(ui, "Cambia password") {
                let (archive, keyfile, oldpw, newpw, newpw2) = (
                    self.cp_archive.clone(),
                    self.cp_keyfile.clone(),
                    self.cp_oldpw.clone(),
                    self.cp_newpw.clone(),
                    self.cp_newpw2.clone(),
                );
                self.run_task(move || {
                    if newpw != newpw2 {
                        return Err("le nuove password non coincidono".into());
                    }
                    let old = load_secret(&keyfile, &oldpw)?;
                    let new = load_secret(&keyfile, &newpw)?;
                    ax::changepw(
                        &PathBuf::from(&archive),
                        &old,
                        &new,
                        &ax::ArgonParams::strong(),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok("Password aggiornata (dati non ricompressi).".into())
                });
            }
        });

        card(ui, "Aggiungi chiave", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.ak_archive, Pick::File);
            path_row(ui, "Keyfile", &mut self.ak_keyfile, Pick::File);
            pw_row(ui, "Password valida", &mut self.ak_existpw);
            pw_row(ui, "Nuova password", &mut self.ak_newpw);
            strength_bar(ui, &self.ak_newpw);
            ui.add_space(8.0);
            if action(ui, "Aggiungi chiave") {
                let (archive, keyfile, existpw, newpw) = (
                    self.ak_archive.clone(),
                    self.ak_keyfile.clone(),
                    self.ak_existpw.clone(),
                    self.ak_newpw.clone(),
                );
                self.run_task(move || {
                    let existing = load_secret(&keyfile, &existpw)?;
                    let newsec = load_secret(&keyfile, &newpw)?;
                    ax::addkey(
                        &PathBuf::from(&archive),
                        &existing,
                        &newsec,
                        &ax::ArgonParams::strong(),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok("Nuova chiave d'accesso aggiunta.".into())
                });
            }
        });

        card(ui, "Rimuovi chiave", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.rk_archive, Pick::File);
            path_row(ui, "Keyfile", &mut self.rk_keyfile, Pick::File);
            pw_row(ui, "Password autorizzante", &mut self.rk_authpw);
            pw_row(ui, "Password da rimuovere", &mut self.rk_targetpw);
            ui.add_space(8.0);
            if action(ui, "Rimuovi chiave") {
                let (archive, keyfile, authpw, targetpw) = (
                    self.rk_archive.clone(),
                    self.rk_keyfile.clone(),
                    self.rk_authpw.clone(),
                    self.rk_targetpw.clone(),
                );
                self.run_task(move || {
                    let existing = load_secret(&keyfile, &authpw)?;
                    let target = load_secret(&keyfile, &targetpw)?;
                    ax::rmkey(&PathBuf::from(&archive), &existing, &target)
                        .map_err(|e| e.to_string())?;
                    Ok("Chiave d'accesso rimossa.".into())
                });
            }
        });
    }

    fn ui_recovery(&mut self, ui: &mut egui::Ui) {
        card(ui, "Crea recovery record (.rec)", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.pr_archive, Pick::File);
            ui.horizontal(|ui| {
                label(ui, "Ridondanza");
                ui.add(egui::Slider::new(&mut self.pr_redundancy, 1..=50).suffix("%"));
            });
            ui.add_space(8.0);
            if action(ui, "Crea recovery record") {
                let (archive, red) = (self.pr_archive.clone(), self.pr_redundancy);
                self.run_task(move || {
                    let rec = PathBuf::from(format!("{archive}.rec"));
                    let rs = ax::protect(&PathBuf::from(&archive), &rec, red)
                        .map_err(|e| e.to_string())?;
                    Ok(format!(
                        "Recovery record: {} blocchi dati + {} parità (tollera {} danneggiati).",
                        rs.data_count, rs.parity_count, rs.parity_count
                    ))
                });
            }
        });

        card(ui, "Ripara archivio danneggiato", |ui| {
            path_row(ui, "Archivio (.axc)", &mut self.rp_archive, Pick::File);
            path_row(ui, "Recupero (.rec)", &mut self.rp_rec, Pick::File);
            path_row(ui, "Uscita riparata", &mut self.rp_out, Pick::Save);
            ui.add_space(8.0);
            if action(ui, "Ripara") {
                let (archive, rec, out) = (
                    self.rp_archive.clone(),
                    self.rp_rec.clone(),
                    self.rp_out.clone(),
                );
                self.run_task(move || {
                    let rec_path = if rec.trim().is_empty() {
                        PathBuf::from(format!("{archive}.rec"))
                    } else {
                        PathBuf::from(&rec)
                    };
                    let out_path = if out.trim().is_empty() {
                        PathBuf::from(format!("{archive}.repaired"))
                    } else {
                        PathBuf::from(&out)
                    };
                    let r = ax::repair(&PathBuf::from(&archive), &rec_path, &out_path)
                        .map_err(|e| e.to_string())?;
                    if r.already_ok {
                        Ok("Archivio già integro: nessuna riparazione necessaria.".into())
                    } else {
                        Ok(format!(
                            "Riparati {} blocchi. Risultato: {}",
                            r.repaired,
                            out_path.display()
                        ))
                    }
                });
            }
        });
    }
}
