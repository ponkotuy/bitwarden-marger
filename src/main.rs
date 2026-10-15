#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod bw;
mod fonts;
mod merge;
mod model;
mod secret;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_title("Bitwarden Merger"),
        ..Default::default()
    };
    eframe::run_native(
        "Bitwarden Merger",
        options,
        Box::new(|cc| {
            fonts::install_japanese_font(&cc.egui_ctx);
            Ok(Box::new(app::MergerApp::new(cc)))
        }),
    )
}
